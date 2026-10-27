using Mayak.Api.Data;
using Mayak.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

/// <summary>Проверка сеанса приложения и роли. Аккаунт кладётся в HttpContext.Items.</summary>
public sealed class RequireAccount : IEndpointFilter
{
    private readonly string _minRole;
    public RequireAccount(string minRole = Roles.User) => _minRole = minRole;

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var http = ctx.HttpContext;
        var token = Tokens.FromRequest(http.Request);
        if (token == null) return Results.Unauthorized();
        var db = http.RequestServices.GetRequiredService<MayakDb>();
        var hash = Tokens.Hash(token);
        var session = await db.Sessions.Include(s => s.Account).FirstOrDefaultAsync(s => s.TokenHash == hash);
        if (session?.Account == null) return Results.Unauthorized();
        if (Roles.Rank(session.Account.Role) < Roles.Rank(_minRole)) return Results.Json(new { error = "Недостаточно прав" }, statusCode: 403);
        if (DateTime.UtcNow - session.LastUsed > TimeSpan.FromMinutes(5))
        {
            session.LastUsed = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        http.Items[nameof(Account)] = session.Account;
        return await next(ctx);
    }
}

/// <summary>Проверка токена агента. Сервер кладётся в HttpContext.Items.</summary>
public sealed class RequireAgent : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var http = ctx.HttpContext;
        var token = Tokens.FromRequest(http.Request);
        if (token == null) return Results.Unauthorized();
        var db = http.RequestServices.GetRequiredService<MayakDb>();
        var hash = Tokens.Hash(token);
        var server = await db.Servers.FirstOrDefaultAsync(s => s.AgentTokenHash == hash);
        if (server == null) return Results.Unauthorized();
        http.Items[nameof(Server)] = server;
        return await next(ctx);
    }
}

public static class HttpContextExtensions
{
    public static Account Me(this HttpContext http) => (Account)http.Items[nameof(Account)]!;
    public static Server AgentServer(this HttpContext http) => (Server)http.Items[nameof(Server)]!;
}
