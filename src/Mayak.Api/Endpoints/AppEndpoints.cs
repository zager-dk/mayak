using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

public sealed record LoginStart(string? Invite, string? Return);
public sealed record MyDeviceCreate(string? Name, DeviceKind Kind, string? Protocol = null, string? InstallationId = null);
public sealed record MyDevicePatch(string? Name);
public sealed record TelegramLinkConfirm(string? TelegramId);

/// <summary>Приложение: вход через Telegram, свой аккаунт и устройства.</summary>
public static class AppEndpoints
{
    public static void Map(WebApplication app)
    {
        var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");

        // 1. Приложение создаёт запрос и открывает ссылку на бота.
        auth.MapPost("/telegram", async (LoginStart? body, MayakDb db, TelegramClient tg) =>
        {
            if (!tg.Enabled || tg.Username.Length == 0) return Results.Json(new { error = "Вход через Telegram пока недоступен" }, statusCode: 503);
            var old = DateTime.UtcNow - TelegramBotService.LoginLifetime * 6;
            await db.LoginRequests.Where(r => r.CreatedAt < old).ExecuteDeleteAsync();
            string? inviteHash = null;
            if (!string.IsNullOrWhiteSpace(body?.Invite))
            {
                inviteHash = Tokens.Hash(body.Invite.Trim());
                var inv = await db.Invites.FirstOrDefaultAsync(i => i.CodeHash == inviteHash);
                if (inv == null || inv.UsedAt != null || inv.ExpiresAt < DateTime.UtcNow)
                    return Results.Json(new { error = "Приглашение устарело или уже использовано. Попросите новое." }, statusCode: 410);
            }
            var ret = body?.Return is "/admin/" or "/my/" ? body.Return : "/my/";
            var req = new LoginRequest { Id = Tokens.New(18), InviteHash = inviteHash, ReturnPath = ret };
            db.LoginRequests.Add(req);
            await db.SaveChangesAsync();
            return Results.Ok(new { requestId = req.Id, botUrl = tg.StartLink(req.Id), expiresInSeconds = (int)TelegramBotService.LoginLifetime.TotalSeconds });
        });

        // Привязка Telegram к уже вошедшему аккаунту (почта и пароль). Бот привяжет Telegram к этому аккаунту, а не создаст новый.
        auth.MapPost("/telegram/link", async (HttpContext http, MayakDb db, TelegramClient tg) =>
        {
            if (!tg.Enabled || tg.Username.Length == 0) return Results.Json(new { error = "Telegram пока недоступен" }, statusCode: 503);
            var acc = http.Me();
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            if (acc.TelegramId != null) return Results.Conflict(new { error = "Telegram уже привязан", telegram = acc.TelegramUsername, telegramLinked = true });
            var old = DateTime.UtcNow - TelegramBotService.LoginLifetime * 6;
            await db.LoginRequests.Where(r => r.CreatedAt < old).ExecuteDeleteAsync();
            var req = new LoginRequest { Id = Tokens.New(18), LinkAccountId = acc.Id, ReturnPath = "/my/" };
            db.LoginRequests.Add(req);
            await db.SaveChangesAsync();
            return Results.Ok(new { requestId = req.Id, botUrl = tg.StartLink(req.Id), expiresInSeconds = (int)TelegramBotService.LoginLifetime.TotalSeconds });
        }).AddEndpointFilter(new RequireAccount());

        // Второй шаг привязки: человек в приложении подтверждает Telegram, который нажал «Запустить» в боте.
        auth.MapPost("/telegram/link/{id}/confirm", async (string id, TelegramLinkConfirm? body, HttpContext http, MayakDb db, TelegramClient tg) =>
        {
            var acc = http.Me();
            var now = DateTime.UtcNow;
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            var req = await db.LoginRequests.FirstOrDefaultAsync(r => r.Id == id, http.RequestAborted);
            if (req == null || req.LinkAccountId != acc.Id || req.TelegramId is not long telegramId || req.AccountId != null ||
                now - req.CreatedAt > TelegramBotService.LoginLifetime)
                return Results.Json(new { error = "Запрос привязки устарел. Начните привязку заново." }, statusCode: 410);
            // Приложение присылает ID Telegram, который человек видел в вопросе: привязываем только его.
            if (body?.TelegramId is { Length: > 0 } expected && expected != telegramId.ToString(System.Globalization.CultureInfo.InvariantCulture))
                return Results.Json(new { error = "Запрос привязки изменился. Начните привязку заново." }, statusCode: 410);
            await db.Entry(acc).ReloadAsync(http.RequestAborted);
            if (!acc.IsActive(now)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            if (acc.TelegramId != null && acc.TelegramId != telegramId) return Results.Conflict(new { error = "К аккаунту уже привязан другой Telegram" });
            var other = await db.Accounts.FirstOrDefaultAsync(a => a.TelegramId == telegramId && a.Id != acc.Id, http.RequestAborted);
            if (other != null)
            {
                if (!TelegramLink.IsReplaceable(other, await db.Devices.AnyAsync(d => d.AccountId == other.Id, http.RequestAborted)))
                    return Results.Conflict(new { error = "Этот Telegram уже привязан к другому аккаунту Маяка. Напишите администратору." });
                db.Accounts.Remove(other);
                await db.SaveChangesAsync(http.RequestAborted);
            }
            acc.TelegramId = telegramId;
            acc.TelegramUsername = req.TelegramUsername;
            req.AccountId = acc.Id;
            req.Uses = MaxLoginUses; // запрос привязки больше ничего не выдаёт
            db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "telegram.link", Details = $"@{req.TelegramUsername} {telegramId}" });
            await db.SaveChangesAsync(http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            try
            {
                await tg.SendAsync(telegramId, $"Готово: Telegram привязан к аккаунту «{acc.Name}». Сюда будут приходить уведомления о новых устройствах, " +
                                               "а войти теперь можно и через Telegram.", http.RequestAborted);
            }
            catch (Exception) { /* привязка уже сохранена; сообщение необязательно */ }
            return Results.Ok(new { status = "linked", telegram = acc.TelegramUsername, telegramLinked = true });
        }).AddEndpointFilter(new RequireAccount());

        // Вход по ссылке-приглашению из админки — без Telegram (для своих людей). Ссылка одноразовая.
        auth.MapPost("/invite", async (LoginStart? body, HttpContext http, MayakDb db) =>
        {
            if (string.IsNullOrWhiteSpace(body?.Invite)) return Results.BadRequest(new { error = "Нет кода приглашения" });
            var hash = Tokens.Hash(body.Invite.Trim());
            var now = DateTime.UtcNow;
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            var inv = await db.Invites.Include(i => i.Account).FirstOrDefaultAsync(i => i.CodeHash == hash, http.RequestAborted);
            if (inv?.Account == null || inv.UsedAt != null || inv.ExpiresAt <= now)
                return Results.Json(new { error = "Ссылка устарела или уже использована. Попросите новую." }, statusCode: 410);
            if (!inv.Account.Enabled) return Results.Json(new { error = "Доступ ещё не одобрен" }, statusCode: 403);
            if (!inv.Account.IsActive(now)) return Results.Json(new { error = "Срок доступа закончился" }, statusCode: 403);
            var claimed = await db.Invites.Where(i => i.CodeHash == hash && i.UsedAt == null && i.ExpiresAt > now &&
                    i.Account!.Enabled && (i.Account.PaidUntil == null || i.Account.PaidUntil > now))
                .ExecuteUpdateAsync(s => s.SetProperty(i => i.UsedAt, now), http.RequestAborted);
            if (claimed != 1)
            {
                var status = await db.Accounts.AnyAsync(a => a.Id == inv.Account.Id && (!a.Enabled || a.PaidUntil != null && a.PaidUntil <= now), http.RequestAborted) ? 403 : 410;
                var message = status == 403 ? "Доступ не активен" : "Ссылка устарела или уже использована. Попросите новую.";
                return Results.Json(new { error = message }, statusCode: status);
            }
            var token = Tokens.New();
            db.Sessions.Add(new Session { TokenHash = Tokens.Hash(token), AccountId = inv.Account.Id, Client = "invite" });
            db.Audit.Add(new AuditEntry { ActorId = inv.Account.Id, Action = "invite.login", Details = inv.Account.Name });
            await db.SaveChangesAsync(http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            return Results.Ok(new { status = "ok", token, account = AccountView(inv.Account) });
        });

        // 2. Приложение спрашивает, подтвердил ли человек вход в боте.
        auth.MapGet("/telegram/{id}", async (string id, string? client, MayakDb db) =>
        {
            var req = await db.LoginRequests.FirstOrDefaultAsync(r => r.Id == id);
            // Сеанс по одному запросу выдаётся не больше MaxLoginUses раз: на телефоне вход завершает либо
            // исходная вкладка, либо кнопка «Вернуться на сайт» из бота (она может открыться в другом браузере).
            // Запрос привязки сеанс не выдаёт: человек уже вошёл по почте и паролю. После нажатия в боте — ждём
            // подтверждения в приложении (status=confirm), после подтверждения — linked.
            if (req?.LinkAccountId != null)
            {
                if (req.AccountId != null) return Results.Ok(new { status = "linked", telegram = req.TelegramUsername });
                if (DateTime.UtcNow - req.CreatedAt > TelegramBotService.LoginLifetime) return Results.Json(new { status = "expired" }, statusCode: 410);
                if (req.TelegramId == null) return Results.Json(new { status = "pending" }, statusCode: 202);
                return Results.Ok(new { status = "confirm", telegram = req.TelegramUsername, telegramName = req.TelegramName,
                    telegramId = req.TelegramId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) });
            }
            if (req == null || req.Uses >= MaxLoginUses || DateTime.UtcNow - req.CreatedAt > TelegramBotService.LoginLifetime)
                return Results.Json(new { status = "expired" }, statusCode: 410);
            if (req.AccountId == null) return Results.Json(new { status = "pending" }, statusCode: 202);
            var acc = await db.Accounts.FirstAsync(a => a.Id == req.AccountId);
            req.Consumed = true;
            req.Uses++;
            var token = Tokens.New();
            db.Sessions.Add(new Session { TokenHash = Tokens.Hash(token), AccountId = acc.Id, Client = (client ?? "").Trim()[..Math.Min(64, (client ?? "").Trim().Length)] });
            await db.SaveChangesAsync();
            return Results.Ok(new { status = "ok", token, account = AccountView(acc) });
        });

        var me = app.MapGroup("/api").AddEndpointFilter(new RequireAccount());

        me.MapGet("/me", async (HttpContext http, MayakDb db, ClusterService cluster, Mayak.Api.Gateway.GatewayKeys keys, IConfiguration cfg) =>
        {
            var acc = http.Me();
            var devices = await db.Devices.Where(d => d.AccountId == acc.Id).OrderBy(d => d.CreatedAt).ToListAsync();
            var c = await cluster.GetAsync();
            return Results.Ok(new
            {
                account = AccountView(acc),
                devices = devices.Select(DeviceView),
                location = await cluster.LocationAsync(http.RequestAborted),
                ready = c != null,
                xray = c != null && ClusterService.XrayOf(c) != null,
                // Своё приложение показывается в кабинете, когда есть шлюз и адрес, откуда его скачать
                // (App:DownloadUrl). Администраторам — сразу, чтобы проверить до выпуска.
                app = keys.Rsa == null ? null
                    : cfg["App:DownloadUrl"] is { Length: > 0 } url ? new { downloadUrl = (string?)url }
                    : Roles.Rank(acc.Role) >= Roles.Rank(Roles.Admin) ? new { downloadUrl = (string?)null } : null,
            });
        });

        // Кабинет на сайте: человек сам заводит устройство и получает ключ для готовых приложений.
        me.MapPost("/devices", async (MyDeviceCreate body, HttpContext http, MayakDb db, ClusterService cluster, IConfiguration cfg) =>
        {
            var acc = http.Me();
            if (!acc.Enabled) return Results.Json(new { error = "Доступ ещё не одобрен" }, statusCode: 403);
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Срок доступа закончился" }, statusCode: 402);
            var protocol = body.Protocol?.ToLowerInvariant();
            if (protocol is not (null or "awg" or "vless")) return Results.BadRequest(new { error = "protocol must be awg or vless" });
            if (protocol == "vless" && !cfg.GetValue("VlessPool:Enabled", false)) return Results.Json(new { error = "VLESS pool is disabled" }, statusCode: 404);
            if (protocol == "vless" && (string.IsNullOrWhiteSpace(body.InstallationId) || body.InstallationId.Length > 128)) return Results.BadRequest(new { error = "installationId is required for VLESS" });
            var managedProtocol = protocol == "vless" ? "vless" : null;
            var name = string.IsNullOrWhiteSpace(body.Name) ? KindName(body.Kind) : body.Name.Trim();
            if (name.Length > 40) name = name[..40];
            Device? createdDevice = null;
            try
            {
                var d = await cluster.CreateManagedDeviceAsync(acc, name, body.Kind, http.RequestAborted, managedProtocol, body.InstallationId);
                createdDevice = d;
                db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "my.device.create", Details = d.Name });
                await db.SaveChangesAsync();
                var files = await cluster.BuildDeviceFilesAsync(d, acc, http.RequestAborted);
                return Results.Ok(new { device = DeviceView(d), files });
            }
            catch (PoolDeliveryException ex)
            {
                return Results.Json(new { device = createdDevice == null ? null : DeviceView(createdDevice), status = ex.Message }, statusCode: ex.StatusCode);
            }
            catch (DeviceLimitException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 409);
            }
            catch (InvalidOperationException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 503);
            }
        });

        me.MapGet("/devices/{id:guid}/files", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = http.Me();
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id && x.AccountId == acc.Id);
            if (d == null) return Results.NotFound();
            try
            {
                return Results.Ok(await cluster.BuildDeviceFilesAsync(d, acc, http.RequestAborted));
            }
            catch (PoolDeliveryException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: ex.StatusCode);
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        me.MapPatch("/devices/{id:guid}", async (Guid id, MyDevicePatch body, HttpContext http, MayakDb db) =>
        {
            var acc = http.Me();
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id && x.AccountId == acc.Id);
            if (d == null) return Results.NotFound();
            if (!string.IsNullOrWhiteSpace(body.Name)) d.Name = body.Name.Trim()[..Math.Min(40, body.Name.Trim().Length)];
            await db.SaveChangesAsync();
            return Results.Ok(DeviceView(d));
        });

        me.MapDelete("/devices/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = http.Me();
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id && x.AccountId == acc.Id);
            if (d == null) return Results.NotFound();
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            db.Devices.Remove(d);
            await db.SaveChangesAsync(http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        me.MapPost("/devices/{id:guid}/subscription", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster, IConfiguration cfg) =>
        {
            return await cluster.WithPoolStateAsync<IResult>(async now =>
            {
            var acc = http.Me();
            await db.Entry(acc).ReloadAsync(http.RequestAborted);
            if (!acc.IsActive(now)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            var device = await db.Devices.FirstOrDefaultAsync(d => d.Id == id && d.AccountId == acc.Id && d.Enabled);
            if (device == null) return Results.NotFound();
            if (string.IsNullOrWhiteSpace(device.XrayId)) return Results.Conflict(new { error = "Для устройства недоступен VLESS ключ" });
            if (device.ServiceProtocol == "vless")
            {
                var endpoint = device.ExitEndpointId is Guid endpointId ? await db.ExitEndpoints.FirstOrDefaultAsync(e => e.Id == endpointId, http.RequestAborted) : null;
                if (endpoint == null) return Results.Json(new { error = "no_ready_exit" }, statusCode: 503);
                if (!ClusterService.IsPoolReady(endpoint, now)) return Results.Json(new { error = "provisioning" }, statusCode: 503);
            }
            var clusterIdentity = await cluster.GetAsync(http.RequestAborted);
            if (device.ServiceProtocol != "vless" && (clusterIdentity == null || ClusterService.XrayOf(clusterIdentity) == null))
                return Results.Json(new { error = "VLESS пока недоступен" }, statusCode: 503);
            var baseUrl = cfg["PublicUrl"]?.TrimEnd('/');
            if (!TryPublicBaseUrl(baseUrl, out var publicUrl))
                return Results.Json(new { error = "PublicUrl должен быть безопасным абсолютным HTTPS URL (или localhost/127.0.0.1 по HTTP/HTTPS)" }, statusCode: 503);
            var token = Tokens.New(32);
            device.SubscriptionTokenHash = Tokens.Hash(token);
            await db.SaveChangesAsync(http.RequestAborted);
            var url = $"{publicUrl}/sub/{token}";
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            return Results.Ok(new { deviceId = device.Id, url, importUrl = "v2raytun://import/" + url });
            }, http.RequestAborted);
        });

        me.MapDelete("/devices/{id:guid}/subscription", async (Guid id, HttpContext http, MayakDb db) =>
        {
            var acc = http.Me();
            var device = await db.Devices.FirstOrDefaultAsync(d => d.Id == id && d.AccountId == acc.Id);
            if (device == null) return Results.NotFound();
            device.SubscriptionTokenHash = null;
            await db.SaveChangesAsync(http.RequestAborted);
            http.Response.Headers.CacheControl = "no-store";
            return Results.NoContent();
        });

        app.MapGet("/sub/{token}", async (string token, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            return await cluster.WithPoolStateAsync<IResult>(async now =>
            {
            if (string.IsNullOrWhiteSpace(token)) return Results.NotFound();
            var hash = Tokens.Hash(token);
            var device = await db.Devices.Include(d => d.Account).FirstOrDefaultAsync(d => d.SubscriptionTokenHash == hash);
            if (device?.Account == null || !device.Enabled || !device.Account.IsActive(now) || string.IsNullOrEmpty(device.XrayId)) return Results.NotFound();
            var c = await cluster.GetAsync(http.RequestAborted);
            var xray = c == null ? null : ClusterService.ClientXrayOf(c);
            if (c == null || (device.ServiceProtocol != "vless" && xray == null)) return Results.NotFound();
            string link;
            if (device.ServiceProtocol == "vless")
            {
                var endpoint = device.ExitEndpointId is Guid endpointId ? await db.ExitEndpoints.FirstOrDefaultAsync(e => e.Id == endpointId, http.RequestAborted) : null;
                if (endpoint == null || !ClusterService.IsPoolReady(endpoint, now)) return Results.NotFound();
                link = Mayak.Api.Gateway.GatewayEndpoints.BuildPoolLink(endpoint, device);
            }
            else link = Mayak.Core.Xray.XrayConfig.BuildVlessLink(await cluster.PublicHostAsync(c, http.RequestAborted), xray!, device.XrayId, $"{c.Title} · {device.Name}");
            http.Response.Headers["profile-title"] = "base64:" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(c.Title));
            http.Response.Headers["profile-update-interval"] = "12";
            var bodyText = link + "\r\n";
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            return Results.Text(bodyText, "text/plain; charset=utf-8");
            }, http.RequestAborted);
        });

        // Ключ подписки для приложения Маяк (одна на аккаунт, устройства приложение регистрирует само).
        me.MapGet("/app-key", async (string? protocol, HttpContext http, MayakDb db, ClusterService cluster, Mayak.Api.Gateway.GatewayKeys keys, IConfiguration cfg) =>
        {
            var acc = http.Me();
            var requestedProtocol = string.Equals(protocol, "vless", StringComparison.OrdinalIgnoreCase) ? "vless" : "awg";
            if (protocol != null && requestedProtocol == "awg" && !string.Equals(protocol, "awg", StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new { error = "protocol must be awg or vless" });
            if (requestedProtocol == "vless" && !cfg.GetValue("VlessPool:Enabled", false)) return Results.Json(new { error = "VLESS pool is disabled" }, statusCode: 404);
            if (keys.Rsa == null) return Results.Json(new { error = "Приложение Маяк пока не подключено" }, statusCode: 503);
            await using (var tx = await db.Database.BeginTransactionAsync(http.RequestAborted))
            {
                await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
                await db.Entry(acc).ReloadAsync(http.RequestAborted);
                if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
                if (acc.AppKey == null)
                {
                    acc.AppKey = Tokens.New(24);
                    await db.SaveChangesAsync(http.RequestAborted);
                }
                await tx.CommitAsync(http.RequestAborted);
            }
            var c = await cluster.GetAsync();
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            return Results.Ok(new { key = Mayak.Api.Gateway.GatewayEndpoints.SubscriptionKey(acc, c?.Title ?? "Маяк VPN", requestedProtocol) });
        });

        // Ключ этого устройства: приложение после входа по почте и паролю получает токен только для своей установки.
        me.MapPost("/app/device-key", async (DeviceKeyRequest body, HttpContext http, DeviceAccessService access, Mayak.Api.Gateway.GatewayKeys keys, ClusterService cluster) =>
        {
            if (keys.Rsa == null) return Results.Json(new { error = "Приложение Маяк пока не подключено" }, statusCode: 503);
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            var result = await access.IssueAsync(http.Me(), body, http.RequestAborted);
            if (result.Status == 409 && result.Code == "DEVICE_LIMIT")
                return Results.Json(new { error = result.Error, code = result.Code, maxDevices = result.MaxDevices,
                    devices = result.Devices!.Select(DeviceAccess.View) }, statusCode: 409);
            if (result.Status != 200) return Results.Json(new { error = result.Error }, statusCode: result.Status);
            var c = await cluster.GetAsync(http.RequestAborted);
            return Results.Ok(new
            {
                key = Mayak.Api.Gateway.GatewayEndpoints.SubscriptionKey(result.Token!, c?.Title ?? "Маяк VPN"),
                deviceId = result.Device!.Id,
                deviceName = result.Device.Name,
                // true — устройство уже было в этом аккаунте (та же установка или переустановка): приложение может заменить ключ на месте.
                reused = result.Reused,
                maxDevices = result.MaxDevices,
            });
        }).RequireRateLimiting("device-key");

        me.MapPost("/app-key/reset", async (HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = http.Me();
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await db.Entry(acc).ReloadAsync(http.RequestAborted);
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            acc.AppKey = Tokens.New(24);
            // Устройства, работавшие по ключу аккаунта, перестают работать: им нужен новый ключ.
            // Устройства со своим токеном (вход по почте и паролю) от ключа аккаунта не зависят и остаются.
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await db.Devices.Where(d => d.AccountId == acc.Id && d.InstallationId != null && d.AppTokenHash == null).ExecuteDeleteAsync();
            db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "my.app-key.reset" });
            await db.SaveChangesAsync(http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        me.MapPost("/logout", async (HttpContext http, MayakDb db) =>
        {
            var hash = Tokens.Hash(Tokens.FromRequest(http.Request)!);
            await db.Sessions.Where(s => s.TokenHash == hash).ExecuteDeleteAsync();
            return Results.NoContent();
        });
    }

    public const int MaxLoginUses = 2;

    private static bool TryPublicBaseUrl(string? value, out string publicUrl)
    {
        publicUrl = "";
        if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        var local = string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) || uri.Host == "127.0.0.1";
        if (uri.Scheme != Uri.UriSchemeHttps && !(local && uri.Scheme == Uri.UriSchemeHttp)) return false;
        publicUrl = value.TrimEnd('/');
        return true;
    }

    public static string KindName(DeviceKind k) => k switch
    {
        DeviceKind.IPhone => "iPhone",
        DeviceKind.Android => "Android",
        DeviceKind.Windows => "Компьютер",
        DeviceKind.Mac => "Mac",
        DeviceKind.Linux => "Linux",
        _ => "Устройство",
    };

    public static object AccountView(Account a) => new
    {
        a.Id,
        a.Name,
        a.Role,
        a.Enabled,
        active = a.IsActive(DateTime.UtcNow),
        a.PaidUntil,
        a.MaxDevices,
        a.DownMbps,
        a.UpMbps,
        email = a.LoginEmailNormalized,
        hasPassword = a.PasswordHash != null,
        telegram = a.TelegramUsername,
        telegramLinked = a.TelegramId != null,
    };

    public static object DeviceView(Device d) => new
    {
        d.Id,
        d.Name,
        kind = d.Kind.ToString(),
        d.Ip,
        d.Enabled,
        d.CreatedAt,
        d.LastHandshake,
        d.RxBytes,
        d.TxBytes,
        canExport = !string.IsNullOrEmpty(d.AwgPrivateKey),
        lastSeen = DeviceAccess.LastSeen(d),
        deviceKey = d.AppTokenHash != null,
    };
}
