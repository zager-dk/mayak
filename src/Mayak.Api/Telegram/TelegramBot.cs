using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Telegram;

public sealed class TelegramOptions
{
    public string Token { get; set; } = "";
    /// <summary>Необязательный прокси для api.telegram.org, например socks5://127.0.0.1:10808.</summary>
    public string? Proxy { get; set; }
    /// <summary>Новые аккаунты сразу активны (открытая регистрация). Иначе ждут одобрения владельца.</summary>
    public bool AutoApprove { get; set; }
    /// <summary>Адрес сайта (кабинета) для ссылок в сообщениях бота. Заполняется из PublicUrl.</summary>
    public string? SiteUrl { get; set; }
    /// <summary>Адрес сервиса (https://домен) — для кнопки «Вернуться на сайт».</summary>
    public string? PublicUrl { get; set; }
}

/// <summary>Тонкий клиент Bot API (getMe, getUpdates, sendMessage).</summary>
public class TelegramClient
{
    private readonly HttpClient _http;
    public string Username { get; protected set; } = "";
    public bool Enabled { get; }

    public TelegramClient(TelegramOptions opt)
    {
        Enabled = !string.IsNullOrWhiteSpace(opt.Token);
        var handler = new SocketsHttpHandler();
        if (!string.IsNullOrWhiteSpace(opt.Proxy)) handler.Proxy = new System.Net.WebProxy(opt.Proxy);
        _http = new HttpClient(handler) { BaseAddress = new Uri($"https://api.telegram.org/bot{opt.Token.Trim()}/"), Timeout = TimeSpan.FromSeconds(40) };
    }

    private async Task<JsonNode?> CallAsync(string method, object args, CancellationToken ct)
    {
        using var resp = await _http.PostAsJsonAsync(method, args, ct);
        var json = await resp.Content.ReadFromJsonAsync<JsonNode>(cancellationToken: ct);
        if (json?["ok"]?.GetValue<bool>() != true)
            throw new InvalidOperationException($"Telegram {method}: {json?["description"]}");
        return json["result"];
    }

    public async Task InitAsync(CancellationToken ct)
    {
        var me = await CallAsync("getMe", new { }, ct);
        Username = me?["username"]?.GetValue<string>() ?? "";
    }

    public async Task<JsonArray> GetUpdatesAsync(long offset, CancellationToken ct) =>
        (await CallAsync("getUpdates", new { offset, timeout = 25, allowed_updates = new[] { "message" } }, ct))?.AsArray() ?? new JsonArray();

    public virtual Task SendAsync(long chatId, string text, CancellationToken ct) =>
        CallAsync("sendMessage", new { chat_id = chatId, text, disable_web_page_preview = true }, ct);

    /// <summary>Сообщение с кнопкой-ссылкой под ним.</summary>
    public virtual Task SendAsync(long chatId, string text, string buttonText, string buttonUrl, CancellationToken ct) =>
        CallAsync("sendMessage", new
        {
            chat_id = chatId,
            text,
            disable_web_page_preview = true,
            reply_markup = new { inline_keyboard = new[] { new[] { new { text = buttonText, url = buttonUrl } } } },
        }, ct);

    public string StartLink(string payload) => $"https://t.me/{Username}?start={payload}";
}

/// <summary>
/// Бот Маяка: подтверждает вход в приложении, сообщает владельцу о новых людях,
/// принимает /approve от администраторов. Работает через long polling — входящих портов не нужно.
/// </summary>
public sealed class TelegramBotService : BackgroundService
{
    public static readonly TimeSpan LoginLifetime = TimeSpan.FromMinutes(10);

    private readonly TelegramClient _tg;
    private readonly TelegramOptions _opt;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<TelegramBotService> _log;

    public TelegramBotService(TelegramClient tg, TelegramOptions opt, IServiceScopeFactory scopes, ILogger<TelegramBotService> log)
    {
        _tg = tg;
        _opt = opt;
        _scopes = scopes;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!_tg.Enabled)
        {
            _log.LogWarning("Токен Telegram не задан — вход через бота выключен.");
            return;
        }
        long offset = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_tg.Username.Length == 0)
                {
                    await _tg.InitAsync(ct);
                    _log.LogInformation("Бот @{Bot} запущен", _tg.Username);
                }
                foreach (var u in await _tg.GetUpdatesAsync(offset, ct))
                {
                    offset = Math.Max(offset, u!["update_id"]!.GetValue<long>() + 1);
                    var msg = u["message"];
                    if (msg == null) continue;
                    try { await HandleAsync(msg, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "Ошибка обработки сообщения бота"); }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.LogWarning("Telegram недоступен: {Error}", ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
            }
        }
    }

    internal async Task HandleAsync(JsonNode msg, CancellationToken ct)
    {
        var text = msg["text"]?.GetValue<string>()?.Trim() ?? "";
        var from = msg["from"];
        if (from == null || from["is_bot"]?.GetValue<bool>() == true) return;
        long chatId = msg["chat"]!["id"]!.GetValue<long>();
        long userId = from["id"]!.GetValue<long>();
        var username = from["username"]?.GetValue<string>();
        var name = string.Join(" ", new[] { from["first_name"]?.GetValue<string>(), from["last_name"]?.GetValue<string>() }.Where(s => !string.IsNullOrWhiteSpace(s)));

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var me = await db.Accounts.FirstOrDefaultAsync(a => a.TelegramId == userId, ct);

        var parts = text.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        var cmd = parts.Length > 0 ? parts[0].Split('@')[0].ToLowerInvariant() : "";
        var arg = parts.Length > 1 ? parts[1].Trim() : "";

        switch (cmd)
        {
            case "/start" when arg.Length > 0:
                await ConfirmLoginAsync(db, arg, me, userId, username, name, chatId, ct);
                break;
            case "/start":
                await _tg.SendAsync(chatId, "Это бот Маяка. Чтобы войти, нажмите «Войти через Telegram» на сайте или в приложении Маяк VPN — откроется этот чат, останется нажать «Запустить»." +
                    (_opt.SiteUrl is { Length: > 0 } site ? $"\nСайт: {site}" : ""), ct);
                break;
            case "/id":
                await _tg.SendAsync(chatId, $"Ваш Telegram ID: {userId}", ct);
                break;
            case "/me":
                await _tg.SendAsync(chatId, me == null ? "Вы ещё не входили в Маяк." : Describe(me), ct);
                break;
            case "/approve" when me != null && Roles.Rank(me.Role) >= Roles.Rank(Roles.Admin):
                await ApproveAsync(db, arg, me, chatId, ct);
                break;
            default:
                await _tg.SendAsync(chatId, "Команды: /me — ваш доступ, /id — ваш Telegram ID.", ct);
                break;
        }
    }

    private async Task ConfirmLoginAsync(MayakDb db, string requestId, Account? me, long userId, string? username, string name, long chatId, CancellationToken ct)
    {
        var req = await db.LoginRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct);
        if (req == null || req.Uses > 0 || req.AccountId != null || DateTime.UtcNow - req.CreatedAt > LoginLifetime)
        {
            await _tg.SendAsync(chatId, "Ссылка для входа устарела. Нажмите «Войти через Telegram» в приложении ещё раз.", ct);
            return;
        }

        // Пришёл по приглашению: привязываем Telegram к уже заведённому аккаунту (со всеми его устройствами).
        bool invited = false;
        if (req.InviteHash != null)
        {
            var inv = await db.Invites.Include(i => i.Account).FirstOrDefaultAsync(i => i.CodeHash == req.InviteHash, ct);
            if (inv?.Account == null || inv.UsedAt != null || inv.ExpiresAt < DateTime.UtcNow)
            {
                await _tg.SendAsync(chatId, "Приглашение устарело или уже использовано. Попросите новую ссылку.", ct);
                return;
            }
            var target = inv.Account;
            if (target.TelegramId != null && target.TelegramId != userId)
            {
                await _tg.SendAsync(chatId, "Этот аккаунт уже привязан к другому Telegram. Напишите администратору.", ct);
                return;
            }
            if (me != null && me.Id != target.Id)
            {
                // Человек уже успел войти сам и получил пустой аккаунт — заменяем его приглашённым.
                bool empty = me.Role == Roles.User && !await db.Devices.AnyAsync(d => d.AccountId == me.Id, ct);
                if (!empty)
                {
                    await _tg.SendAsync(chatId, "Ваш Telegram уже привязан к другому аккаунту Маяка с устройствами. Напишите администратору — он объединит их.", ct);
                    return;
                }
                db.Accounts.Remove(me);
                await db.SaveChangesAsync(ct);
            }
            target.TelegramId = userId;
            target.TelegramUsername = username;
            target.Enabled = true;
            inv.UsedAt = DateTime.UtcNow;
            db.Audit.Add(new AuditEntry { ActorId = target.Id, Action = "invite.accept", Details = $"{target.Name} @{username} {userId}" });
            me = target;
            invited = true;
        }

        bool isNew = me == null;
        if (me == null)
        {
            bool first = !await db.Accounts.AnyAsync(a => a.TelegramId != null, ct) && !await db.Accounts.AnyAsync(a => a.Role == Roles.Owner, ct);
            me = new Account
            {
                Name = name.Length > 0 ? name : username ?? $"tg{userId}",
                TelegramId = userId,
                TelegramUsername = username,
                // Самый первый человек — владелец: сервис ставят для себя.
                Role = first ? Roles.Owner : Roles.User,
                Enabled = first || _opt.AutoApprove,
            };
            db.Accounts.Add(me);
        }
        else
        {
            me.TelegramUsername = username;
        }
        req.TelegramId = userId;
        req.TelegramUsername = username;
        req.TelegramName = name;
        req.AccountId = me.Id;
        db.Audit.Add(new AuditEntry { ActorId = me.Id, Action = "login.telegram", Details = $"@{username} {userId}" });
        await db.SaveChangesAsync(ct);

        var text = !me.Enabled ? "Заявка на доступ отправлена. Как только её одобрят, я напишу сюда — и на сайте можно будет получить ключ."
            : isNew && me.Role == Roles.Owner ? "Готово: вы вошли и назначены владельцем Маяка."
            : invited ? $"Готово: вы вошли как «{me.Name}». На сайте — ваши устройства и ключи."
            : "Готово: вход подтверждён.";
        // Telegram сам не возвращает в браузер — даём кнопку, которая завершает вход на сайте.
        if (_opt.PublicUrl is { Length: > 0 } baseUrl)
            await _tg.SendAsync(chatId, text, "Вернуться на сайт", $"{baseUrl.TrimEnd('/')}{req.ReturnPath ?? "/my/"}?login={Uri.EscapeDataString(req.Id)}", ct);
        else
            await _tg.SendAsync(chatId, text + " Вернитесь на сайт.", ct);

        if (!me.Enabled)
        {
            if (isNew) await NotifyAdminsAsync(db, $"Новый человек просит доступ: {me.Name}" + (username != null ? $" (@{username})" : "") +
                                                   $"\nОдобрить: /approve {me.Id.ToString()[..8]}", ct);
        }
    }

    private async Task ApproveAsync(MayakDb db, string arg, Account admin, long chatId, CancellationToken ct)
    {
        var prefix = arg.Trim().ToLowerInvariant();
        if (prefix.Length < 6)
        {
            var waiting = await db.Accounts.Where(a => !a.Enabled).OrderByDescending(a => a.CreatedAt).Take(10).ToListAsync(ct);
            await _tg.SendAsync(chatId, waiting.Count == 0 ? "Заявок нет." :
                "Ждут одобрения:\n" + string.Join("\n", waiting.Select(a => $"{a.Name}" + (a.TelegramUsername != null ? $" @{a.TelegramUsername}" : "") + $" — /approve {a.Id.ToString()[..8]}")), ct);
            return;
        }
        var candidates = await db.Accounts.Where(a => !a.Enabled).ToListAsync(ct);
        var acc = candidates.FirstOrDefault(a => a.Id.ToString().StartsWith(prefix));
        if (acc == null)
        {
            await _tg.SendAsync(chatId, "Такой заявки нет.", ct);
            return;
        }
        acc.Enabled = true;
        db.Audit.Add(new AuditEntry { ActorId = admin.Id, Action = "account.approve", Details = acc.Id.ToString() });
        await db.SaveChangesAsync(ct);
        await new ClusterService(db).BumpAsync(ct);
        await _tg.SendAsync(chatId, $"Доступ для «{acc.Name}» включён.", ct);
        if (acc.TelegramId is long tid) await _tg.SendAsync(tid, "Доступ к Маяку одобрен — можно подключаться." + (_opt.SiteUrl is { Length: > 0 } site ? $"\nКлюч для приложения: {site}" : ""), ct);
    }

    private async Task NotifyAdminsAsync(MayakDb db, string text, CancellationToken ct)
    {
        var admins = await db.Accounts.Where(a => a.TelegramId != null && (a.Role == Roles.Owner || a.Role == Roles.Admin)).Select(a => a.TelegramId!.Value).ToListAsync(ct);
        foreach (var id in admins)
        {
            try { await _tg.SendAsync(id, text, ct); }
            catch (Exception ex) { _log.LogWarning("Не удалось уведомить {Id}: {Error}", id, ex.Message); }
        }
    }

    private static string Describe(Account a)
    {
        var until = a.PaidUntil == null ? "без срока" : $"до {a.PaidUntil:dd.MM.yyyy}";
        var state = a.Enabled ? "включён" : "ждёт одобрения";
        return $"{a.Name}\nДоступ: {state}, {until}\nУстройств: до {a.MaxDevices}, скорость до {(a.DownMbps == 0 ? "без лимита" : a.DownMbps + " Мбит/с")}";
    }
}
