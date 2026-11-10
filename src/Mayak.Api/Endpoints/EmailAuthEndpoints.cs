using Mayak.Api.Data;
using Mayak.Api.Services;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Mayak.Api.Endpoints;

public sealed record EmailRegisterRequest(string? Invite, string? Email, string? Password);
public sealed record EmailCredentialsRequest(string? Email, string? Password);

public static class EmailAuthEndpoints
{
    public static void Map(WebApplication app)
    {
        var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");
        auth.MapPost("/register", RegisterSafe);
        auth.MapPost("/login", Login);
        app.MapPost("/api/auth/credentials", SetCredentialsSafe).AddEndpointFilter(new RequireAccount()).RequireRateLimiting("auth");
    }

    private static async Task<IResult> RegisterSafe(EmailRegisterRequest body, HttpContext http, MayakDb db)
    {
        try { return await Register(body, http, db); }
        catch (Exception ex) when (IsUniqueViolation(ex))
        { return Results.Conflict(new { error = "Этот адрес уже используется. Обратитесь к администратору." }); }
    }

    private static async Task<IResult> SetCredentialsSafe(EmailCredentialsRequest body, HttpContext http, MayakDb db)
    {
        try { return await SetCredentials(body, http, db); }
        catch (Exception ex) when (IsUniqueViolation(ex))
        { return Results.Conflict(new { error = "Этот адрес уже используется. Обратитесь к администратору." }); }
    }

    private static bool IsUniqueViolation(Exception exception)
    {
        for (var current = exception; current != null; current = current.InnerException!)
            if (current is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation }) return true;
        return false;
    }

    private static async Task<IResult> Register(EmailRegisterRequest body, HttpContext http, MayakDb db)
    {
        if (string.IsNullOrWhiteSpace(body.Invite)) return Results.BadRequest(new { error = "Нет кода приглашения." });
        var valid = Validate(body.Email, body.Password, out var normalized, out var error);
        if (!valid) return Results.BadRequest(new { error });
        var hash = PasswordCredentials.Hash(body.Password!);
        var now = DateTime.UtcNow;
        // The invite claim and conditional null-password update are the serialization points.
        // Read committed avoids turning a normal concurrent redemption into an exposed 500.
        await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, http.RequestAborted);
        var inviteHash = Tokens.Hash(body.Invite.Trim());
        var invite = await db.Invites.Include(i => i.Account).FirstOrDefaultAsync(i => i.CodeHash == inviteHash, http.RequestAborted);
        if (invite?.Account == null || invite.UsedAt != null || invite.ExpiresAt <= now)
            return Results.Json(new { error = "Приглашение устарело или уже использовано. Попросите новое." }, statusCode: 410);
        if (!invite.Account.Enabled) return Results.Json(new { error = "Доступ ещё не одобрен." }, statusCode: 403);
        if (!invite.Account.IsActive(now)) return Results.Json(new { error = "Срок доступа закончился." }, statusCode: 403);
        if (invite.Account.PasswordHash != null) return Results.Conflict(new { error = "Для этого аккаунта пароль уже задан. Обратитесь к администратору." });
        if (await db.Accounts.AnyAsync(a => a.LoginEmailNormalized == normalized, http.RequestAborted))
            return Results.Conflict(new { error = "Этот адрес уже используется. Обратитесь к администратору." });

        var claimed = await db.Invites.Where(i => i.CodeHash == inviteHash && i.UsedAt == null && i.ExpiresAt > now && i.Account!.Enabled && (i.Account.PaidUntil == null || i.Account.PaidUntil > now))
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.UsedAt, now), http.RequestAborted);
        if (claimed != 1) return Results.Json(new { error = "Приглашение устарело или уже использовано. Попросите новое." }, statusCode: 410);
        var bound = await db.Accounts.Where(a => a.Id == invite.AccountId && a.PasswordHash == null && a.Enabled && (a.PaidUntil == null || a.PaidUntil > now))
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.LoginEmailNormalized, normalized).SetProperty(a => a.PasswordHash, hash), http.RequestAborted);
        if (bound != 1) return Results.Conflict(new { error = "Для этого аккаунта пароль уже задан. Обратитесь к администратору." });
        return await Finish(db, http, invite.AccountId, "email-register", tx);
    }

    private static async Task<IResult> SetCredentials(EmailCredentialsRequest body, HttpContext http, MayakDb db)
    {
        var account = http.Me();
        var now = DateTime.UtcNow;
        if (!account.IsActive(now)) return Results.Json(new { error = "Доступ не активен. Обратитесь к администратору." }, statusCode: 403);
        if (account.PasswordHash != null) return Results.Conflict(new { error = "Для этого аккаунта пароль уже задан. Обратитесь к администратору." });
        if (!Validate(body.Email, body.Password, out var normalized, out var error)) return Results.BadRequest(new { error });
        if (await db.Accounts.AnyAsync(a => a.LoginEmailNormalized == normalized, http.RequestAborted))
            return Results.Conflict(new { error = "Этот адрес уже используется. Обратитесь к администратору." });
        await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, http.RequestAborted);
        var hash = PasswordCredentials.Hash(body.Password!);
        var changed = await db.Accounts.Where(a => a.Id == account.Id && a.PasswordHash == null && a.Enabled && (a.PaidUntil == null || a.PaidUntil > now))
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.LoginEmailNormalized, normalized).SetProperty(a => a.PasswordHash, hash), http.RequestAborted);
        if (changed != 1)
        {
            var active = await db.Accounts.AnyAsync(a => a.Id == account.Id && a.Enabled && (a.PaidUntil == null || a.PaidUntil > now), http.RequestAborted);
            return active ? Results.Conflict(new { error = "Для этого аккаунта пароль уже задан. Обратитесь к администратору." })
                : Results.Json(new { error = "Доступ не активен. Обратитесь к администратору." }, statusCode: 403);
        }
        return await Finish(db, http, account.Id, "email-credentials", tx);
    }

    private static async Task<IResult> Login(EmailCredentialsRequest body, HttpContext http, MayakDb db)
    {
        if (!Validate(body.Email, body.Password, out var normalized, out _))
        {
            PasswordCredentials.Verify(body.Password ?? "", null);
            return Results.Json(new { error = "Неверный адрес или пароль." }, statusCode: 401);
        }
        var account = await db.Accounts.FirstOrDefaultAsync(a => a.LoginEmailNormalized == normalized, http.RequestAborted);
        var verified = PasswordCredentials.Verify(body.Password!, account?.PasswordHash);
        if (!verified || account == null) return Results.Json(new { error = "Неверный адрес или пароль." }, statusCode: 401);
        return await Issue(db, http, account.Id, "email-login");
    }

    private static bool Validate(string? email, string? password, out string normalized, out string error)
    {
        normalized = ""; error = "";
        try { normalized = PasswordCredentials.NormalizeEmail(email); }
        catch (ArgumentException e) { error = e.Message; return false; }
        if (!PasswordCredentials.ValidPassword(password)) { error = "Пароль должен содержать от 12 до 128 символов."; return false; }
        return true;
    }

    private static async Task<IResult> Finish(MayakDb db, HttpContext http, Guid accountId, string client, Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx)
    {
        var response = await Issue(db, http, accountId, client);
        if (response is IStatusCodeHttpResult { StatusCode: >= 400 }) await tx.RollbackAsync(http.RequestAborted);
        else await tx.CommitAsync(http.RequestAborted);
        return response;
    }

    private static async Task<IResult> Issue(MayakDb db, HttpContext http, Guid accountId, string client)
    {
        // Bind eligibility and session creation to a single row-lock linearization point.
        // A concurrent disable/expiry update either commits first and is observed here, or waits
        // until this session transaction commits before taking effect.
        var ownsTransaction = db.Database.CurrentTransaction == null;
        await using var ownedTransaction = ownsTransaction
            ? await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, http.RequestAborted)
            : null;

        // Earlier credential setup used ExecuteUpdate, which intentionally bypasses EF tracking.
        db.ChangeTracker.Clear();
        var account = await db.Accounts
            .FromSqlInterpolated($"SELECT * FROM \"Accounts\" WHERE \"Id\" = {accountId} FOR UPDATE")
            .FirstOrDefaultAsync(http.RequestAborted);
        if (account == null) return Results.Unauthorized();
        var now = DateTime.UtcNow;
        if (!account.Enabled) return Results.Json(new { error = "Доступ отключён. Обратитесь к администратору." }, statusCode: 403);
        if (!account.IsActive(now)) return Results.Json(new { error = "Срок доступа закончился." }, statusCode: 403);
        await db.Entry(account).Collection(a => a.Devices).LoadAsync(http.RequestAborted);
        var token = Tokens.New();
        db.Sessions.Add(new Session { TokenHash = Tokens.Hash(token), AccountId = accountId, Client = client });
        db.Audit.Add(new AuditEntry { ActorId = accountId, Action = client, Details = "" });
        await db.SaveChangesAsync(http.RequestAborted);
        if (ownedTransaction != null) await ownedTransaction.CommitAsync(http.RequestAborted);
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";
        return Results.Ok(new { status = "ok", token, account = AppEndpoints.AccountView(account) });
    }
}
