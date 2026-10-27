using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

/// <summary>Приложение: вход через Telegram, свой аккаунт и устройства.</summary>
public static class AppEndpoints
{
    public static void Map(WebApplication app)
    {
        var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");

        // 1. Приложение создаёт запрос и открывает ссылку на бота.
        auth.MapPost("/telegram", async (MayakDb db, TelegramClient tg) =>
        {
            if (!tg.Enabled || tg.Username.Length == 0) return Results.Json(new { error = "Вход через Telegram пока недоступен" }, statusCode: 503);
            var old = DateTime.UtcNow - TelegramBotService.LoginLifetime * 6;
            await db.LoginRequests.Where(r => r.CreatedAt < old).ExecuteDeleteAsync();
            var req = new LoginRequest { Id = Tokens.New(18) };
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

        me.MapGet("/me", async (HttpContext http, MayakDb db) =>
        {
            var acc = http.Me();
            var devices = await db.Devices.Where(d => d.AccountId == acc.Id).OrderBy(d => d.CreatedAt).ToListAsync();
            return Results.Ok(new { account = AccountView(acc), devices = devices.Select(DeviceView) });
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

        me.MapPost("/logout", async (HttpContext http, MayakDb db) =>
        {
            var hash = Tokens.Hash(Tokens.FromRequest(http.Request)!);
            await db.Sessions.Where(s => s.TokenHash == hash).ExecuteDeleteAsync();
            return Results.NoContent();
        });
    }

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
