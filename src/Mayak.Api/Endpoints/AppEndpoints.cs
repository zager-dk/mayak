using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

public sealed record LoginStart(string? Invite);
public sealed record MyDeviceCreate(string? Name, DeviceKind Kind);
public sealed record MyDevicePatch(string? Name);

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
            var req = new LoginRequest { Id = Tokens.New(18), InviteHash = inviteHash };
            db.LoginRequests.Add(req);
            await db.SaveChangesAsync();
            return Results.Ok(new { requestId = req.Id, botUrl = tg.StartLink(req.Id), expiresInSeconds = (int)TelegramBotService.LoginLifetime.TotalSeconds });
        });

        // 2. Приложение спрашивает, подтвердил ли человек вход в боте.
        auth.MapGet("/telegram/{id}", async (string id, string? client, MayakDb db) =>
        {
            var req = await db.LoginRequests.FirstOrDefaultAsync(r => r.Id == id);
            if (req == null || req.Consumed || DateTime.UtcNow - req.CreatedAt > TelegramBotService.LoginLifetime)
                return Results.Json(new { status = "expired" }, statusCode: 410);
            if (req.AccountId == null) return Results.Json(new { status = "pending" }, statusCode: 202);
            var acc = await db.Accounts.FirstAsync(a => a.Id == req.AccountId);
            req.Consumed = true;
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
                // Своё приложение показывается в кабинете, когда есть шлюз и адрес, откуда его скачать.
                app = keys.Rsa != null && cfg["App:DownloadUrl"] is { Length: > 0 } url ? new { downloadUrl = url } : null,
            });
        });

        // Кабинет на сайте: человек сам заводит устройство и получает ключ для готовых приложений.
        me.MapPost("/devices", async (MyDeviceCreate body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = http.Me();
            if (!acc.Enabled) return Results.Json(new { error = "Доступ ещё не одобрен" }, statusCode: 403);
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Срок доступа закончился" }, statusCode: 402);
            var count = await db.Devices.CountAsync(d => d.AccountId == acc.Id);
            if (count >= acc.MaxDevices) return Results.Json(new { error = $"Можно не больше {acc.MaxDevices} устройств. Удалите ненужное." }, statusCode: 409);
            var name = string.IsNullOrWhiteSpace(body.Name) ? KindName(body.Kind) : body.Name.Trim();
            if (name.Length > 40) name = name[..40];
            try
            {
                var d = await cluster.CreateManagedDeviceAsync(acc, name, body.Kind, http.RequestAborted);
                db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "my.device.create", Details = d.Name });
                await db.SaveChangesAsync();
                return Results.Ok(new { device = DeviceView(d), files = await cluster.BuildDeviceFilesAsync(d, acc, http.RequestAborted) });
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
            db.Devices.Remove(d);
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        // Ключ подписки для приложения Маяк (одна на аккаунт, устройства приложение регистрирует само).
        me.MapGet("/app-key", async (HttpContext http, MayakDb db, ClusterService cluster, Mayak.Api.Gateway.GatewayKeys keys) =>
        {
            var acc = http.Me();
            if (!acc.IsActive(DateTime.UtcNow)) return Results.Json(new { error = "Доступ не активен" }, statusCode: 403);
            if (keys.Rsa == null) return Results.Json(new { error = "Приложение Маяк пока не подключено" }, statusCode: 503);
            if (acc.AppKey == null)
            {
                acc.AppKey = Tokens.New(24);
                await db.SaveChangesAsync();
            }
            var c = await cluster.GetAsync();
            return Results.Ok(new { key = Mayak.Api.Gateway.GatewayEndpoints.SubscriptionKey(acc, c?.Title ?? "Маяк VPN") });
        });

        me.MapPost("/app-key/reset", async (HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = http.Me();
            acc.AppKey = Tokens.New(24);
            // Устройства приложения перестают работать: им нужен новый ключ.
            await db.Devices.Where(d => d.AccountId == acc.Id && d.InstallationId != null).ExecuteDeleteAsync();
            db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "my.app-key.reset" });
            await db.SaveChangesAsync();
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
        telegram = a.TelegramUsername,
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
    };
}
