using Mayak.Api.Data;
using Mayak.Api.Endpoints;
using Mayak.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Provisioning;

public static class ProvisioningEndpoints
{
    public static void Map(WebApplication app, string publicUrl)
    {
        var g = app.MapGroup("/api/admin/provision")
            .AddEndpointFilter(new RequireAccount(Roles.Admin))
            .AddEndpointFilter(new RequireEnabledProvisionAdmin());

        g.MapPost("/host-key", async (ProvisioningHostKeyRequest body, HttpContext http, MayakDb db, IProvisioningBackend backend) =>
        {
            if (!ValidateHost(body.Host, body.Port, publicUrl, out var host, out var error)) return Results.BadRequest(new { error });
            if (await ProvisioningGuards.HostExistsAsync(db, host, null, http.RequestAborted)) return Results.Conflict(new { error = "Этот адрес уже зарегистрирован в разделе серверов." });
            try
            {
                var fingerprint = await backend.ReadHostFingerprintAsync(host, body.Port, http.RequestAborted);
                if (!ProvisioningRules.ValidFingerprint(fingerprint)) return Results.BadRequest(new { error = "SSH вернул некорректный fingerprint." });
                return Results.Ok(new { host, port = body.Port, fingerprint });
            }
            catch (Exception)
            {
                return Results.BadRequest(new { error = "Не удалось получить SSH fingerprint без учётных данных. Проверьте адрес, порт и доступность SSH." });
            }
        });

        g.MapPost("/inspect", async (ProvisioningInspectRequest body, HttpContext http, MayakDb db,
            IProvisioningBackend backend, IConfiguration cfg) =>
        {
            if (!ValidateCredentials(body.Host, body.Port, body.User, body.Password, body.TrustedFingerprint,
                    body.TrustFingerprint, publicUrl, out var host, out var error)) return Results.BadRequest(new { error });
            if (await ProvisioningGuards.HostExistsAsync(db, host, null, http.RequestAborted)) return Results.Conflict(new { error = "Этот адрес уже зарегистрирован в разделе серверов." });
            var (plan, planError) = await ProvisioningPlanner.GetAsync(db, null, null, null, http.RequestAborted);
            if (plan == null) return Results.Conflict(new { error = planError });
            var credentials = new ProvisioningCredentials(host, body.Port, body.User, body.Password, body.TrustedFingerprint);
            body.Password = "";
            try
            {
                var result = await backend.InspectAsync(credentials, plan, http.RequestAborted);
                if (!result.Supported) return Results.Conflict(new { error = result.Reason ?? "Сервер не соответствует требованиям.", inspection = result });
                return Results.Ok(new { inspection = result });
            }
            catch (Exception)
            {
                return Results.BadRequest(new { error = "Не удалось пройти SSH-проверку. Fingerprint должен совпадать с тем, который вы сверили; проверьте учётные данные и повторите этап проверки." });
            }
            finally { credentials.Password = ""; }
        });

        g.MapPost("/start", async (ProvisioningStartRequest body, HttpContext http, MayakDb db, ClusterService cluster,
            IProvisioningBackend backend, ProvisioningCoordinator coordinator) =>
        {
            if (!body.ConfirmBlankServer) return Results.BadRequest(new { error = "Подтвердите установку на этот сервер." });
            if (!ValidateCredentials(body.Host, body.Port, body.User, body.Password, body.TrustedFingerprint,
                    body.TrustFingerprint, publicUrl, out var host, out var error)) return Results.BadRequest(new { error });
            if (string.IsNullOrWhiteSpace(body.Name) || body.Name.Trim().Length > 100)
                return Results.BadRequest(new { error = "Укажите название сервера не длиннее 100 символов." });
            if (body.AwgPort is < 1 or > 65535 || body.XrayPort is < 1 or > 65535 || body.AwgPort == body.XrayPort)
                return Results.BadRequest(new { error = "Некорректные порты; вернитесь к повторной проверке сервера." });
            if (await ProvisioningGuards.HostExistsAsync(db, host, null, http.RequestAborted)) return Results.Conflict(new { error = "Этот адрес уже зарегистрирован в разделе серверов." });

            var (plan, planError) = await ProvisioningPlanner.GetAsync(db, body.AwgPort, body.XrayPort, null, http.RequestAborted);
            if (plan == null) return Results.Conflict(new { error = planError });
            var credentials = new ProvisioningCredentials(host, body.Port, body.User, body.Password, body.TrustedFingerprint);
            body.Password = "";
            var handedOff = false;
            var actorId = http.Me().Id;
            var sessionToken = Tokens.FromRequest(http.Request);
            var sessionHash = sessionToken == null ? "" : Tokens.Hash(sessionToken);
            try
            {
                try
                {
                    var inspection = await backend.InspectAsync(credentials, plan, http.RequestAborted);
                    if (!inspection.Supported) return Results.Conflict(new { error = inspection.Reason ?? "Сервер не соответствует требованиям." });
                    if (inspection.Occupied && !body.Overwrite)
                        return Results.Conflict(new { error = "На сервере уже есть VPN, контейнеры или агент. Подтвердите перезапись.", inspection });
                }
                catch (Exception)
                {
                    return Results.BadRequest(new { error = "Финальная read-only проверка SSH не прошла. Сервер не добавлен и установка не началась." });
                }

                if (string.IsNullOrEmpty(sessionHash) || !await IsCurrentEnabledAdminAsync(db, actorId, sessionHash, http.RequestAborted))
                    return Results.Json(new { error = "Учётная запись или административные права изменились; установка не поставлена в очередь." }, statusCode: 403);

                if (!coordinator.TryReserve(host, out var reservation) || reservation == null)
                    return Results.Conflict(new { error = "Уже идёт установка на этот адрес или очередь занята. Повторите позже." });
                using (reservation)
                {
                    await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
                    await ProvisioningGuards.AcquireHostMutationLockAsync(db, http.RequestAborted);
                    if (!await IsCurrentEnabledAdminAsync(db, actorId, sessionHash, http.RequestAborted))
                        return Results.Json(new { error = "Учётная запись или административные права изменились; установка не поставлена в очередь." }, statusCode: 403);
                    if (await ProvisioningGuards.HostExistsAsync(db, host, null, http.RequestAborted))
                        return Results.Conflict(new { error = "Этот адрес уже зарегистрирован в разделе серверов." });
                    var token = Tokens.New();
                    var server = new Server
                    {
                        Name = body.Name.Trim(), Role = ServerRoles.Exit, Host = host,
                        City = body.City?.Trim() ?? "", Country = body.Country?.Trim() ?? "",
                        CountryCode = "", AgentTokenHash = Tokens.Hash(token), Active = false,
                        TrustedHostFingerprint = body.TrustedFingerprint,
                        ProvisioningStatus = "queued", ProvisioningMessage = "Установка поставлена в очередь.",
                        ProvisioningUpdatedAt = DateTime.UtcNow,
                    };
                    db.Servers.Add(server);
                    db.Audit.Add(new AuditEntry { ActorId = http.Me().Id, Action = "server.provision.start", Details = $"{host} {body.TrustedFingerprint}{(body.Overwrite ? " overwrite" : "")}" });
                    await db.SaveChangesAsync(http.RequestAborted);
                    await tx.CommitAsync(http.RequestAborted);
                    reservation.Start(server.Id, credentials, token, plan, publicUrl, actorId, sessionHash, body.Overwrite);
                    handedOff = true;
                    return Results.Accepted($"/api/admin/provision/jobs/{server.Id}", new { jobId = server.Id, serverId = server.Id, status = server.ProvisioningStatus });
                }
            }
            finally { if (!handedOff) credentials.Password = ""; }
        });

        g.MapGet("/jobs/{id:guid}", async (Guid id, MayakDb db) =>
        {
            var s = await db.Servers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id && x.ProvisioningStatus != null);
            if (s == null) return Results.NotFound();
            var clusterIdentity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1);
            return Results.Ok(new { jobId = s.Id, serverId = s.Id, s.Host, s.Name, s.ProvisioningStatus, s.ProvisioningMessage,
                s.ProvisioningUpdatedAt, s.ProvisionIdentityMatched, s.ProvisioningConfirmedRevision, s.ProvisioningConfirmedAt,
                provisioningReady = ProvisioningGuards.IsReady(s, clusterIdentity, DateTime.UtcNow), s.Active, s.LastSeen, s.AgentVersion });
        });
    }

    private static bool ValidateHost(string? input, int port, string publicUrl, out string host, out string error)
    {
        if (!ProvisioningRules.TryPublicIpv4(input, publicUrl, out host, out error)) return false;
        if (!ProvisioningRules.ValidSshPort(port)) { error = "Укажите корректный SSH порт."; return false; }
        error = "";
        return true;
    }

    private static bool ValidateCredentials(string? inputHost, int port, string? user, string? password, string? fingerprint,
        bool trustFingerprint, string publicUrl, out string host, out string error)
    {
        if (!ValidateHost(inputHost, port, publicUrl, out host, out error)) return false;
        if (!ProvisioningRules.ValidUser(user)) { error = "Имя SSH-пользователя должно начинаться с буквы или _, содержать до 32 символов [a-z0-9_-]."; return false; }
        if (string.IsNullOrEmpty(password) || password.Length > 512) { error = "Введите SSH-пароль (до 512 символов)."; return false; }
        if (!ProvisioningRules.ValidFingerprint(fingerprint) || !trustFingerprint) { error = "Сверьте fingerprint с сервером и подтвердите доверие."; return false; }
        return true;
    }

    public static Task<bool> IsCurrentEnabledAdminAsync(MayakDb db, Guid accountId, string sessionHash, CancellationToken ct) =>
        db.Sessions.AnyAsync(s => s.TokenHash == sessionHash && s.AccountId == accountId && s.Account!.Enabled &&
            (s.Account.Role == Roles.Admin || s.Account.Role == Roles.Owner), ct);
}

public sealed class RequireEnabledProvisionAdmin : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var account = ctx.HttpContext.Me();
        if (!account.Enabled || account.Role is not (Roles.Admin or Roles.Owner))
            return ValueTask.FromResult<object?>(Results.Json(new { error = "Только активный администратор или владелец может устанавливать серверы." }, statusCode: 403));
        return next(ctx);
    }
}
