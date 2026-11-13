using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Agent;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

/// <summary>Агенты на серверах: знакомство, желаемое состояние, отчёты.</summary>
public static class AgentEndpoints
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/").AddEndpointFilter(new RequireAgent());

        g.MapPost(AgentPaths.Hello, async (AgentHello hello, HttpContext http, MayakDb db, ClusterService cluster, ILogger<Program> log) =>
        {
            var server = http.AgentServer();
            server.LastSeen = DateTime.UtcNow;
            server.AgentVersion = hello.Version;
            int imported = 0;
            if (server.Role == ServerRoles.Exit)
            {
                bool isProvisioning = server.ProvisioningStatus != null;
                if (isProvisioning)
                {
                    if (hello.Identity == null)
                    {
                        FailProvisioning(server, "Агент не прислал identity выхода. Сервер оставлен неактивным.");
                        await db.SaveChangesAsync(http.RequestAborted);
                        return Results.Conflict(new { error = "Provisioned exit did not report its identity." });
                    }
                    var adopted = await cluster.AdoptIdentityAsync(hello.Identity, http.RequestAborted);
                    if (!await cluster.MatchesIdentityAsync(hello.Identity, http.RequestAborted))
                    {
                        FailProvisioning(server, "Identity сервера не совпала с кластером. Сервер оставлен неактивным.");
                        await db.SaveChangesAsync(http.RequestAborted);
                        return Results.Conflict(new { error = "Provisioned exit identity mismatch." });
                    }
                    if (server.ProvisioningStatus is "awaiting_agent" or "syncing" or "installed")
                    {
                        var currentIdentity = await cluster.GetAsync(http.RequestAborted);
                        if (currentIdentity == null)
                        {
                            FailProvisioning(server, "Кластерная identity не найдена. Сервер оставлен неактивным.");
                            await db.SaveChangesAsync(http.RequestAborted);
                            return Results.Conflict(new { error = "Cluster identity unavailable." });
                        }
                        server.ProvisionIdentityMatched = true;
                        server.ProvisioningIdentityHash = Mayak.Api.Provisioning.ProvisioningPlanner.IdentityHash(currentIdentity);
                        server.ProvisioningConfirmedRevision = null;
                        server.ProvisioningConfirmedAt = null;
                        server.ProvisioningStatus = "syncing";
                        server.ProvisioningMessage = "Identity совпала; агент должен подтвердить текущую ревизию и состояние AWG/Xray.";
                        server.ProvisioningUpdatedAt = DateTime.UtcNow;
                    }
                    else
                    {
                        server.ProvisionIdentityMatched = false;
                        server.ProvisioningIdentityHash = null;
                        server.ProvisioningConfirmedRevision = null;
                        server.ProvisioningConfirmedAt = null;
                    }
                    if (adopted) log.LogInformation("Identity первого выхода {Name} принята для кластера", server.Name);
                }
                else if (server.ProvisioningStatus == null && hello.Identity != null && await cluster.AdoptIdentityAsync(hello.Identity, http.RequestAborted))
                    log.LogInformation("Ключи выхода {Name} приняты как общие для всех выходов", server.Name);
                if (hello.Legacy != null)
                {
                    imported = await cluster.ImportLegacyAsync(hello.Legacy, http.RequestAborted);
                    if (imported > 0) log.LogInformation("С {Name} перенесено устройств: {Count}", server.Name, imported);
                }
            }
            db.Audit.Add(new AuditEntry { Action = "agent.hello", Details = $"{server.Name} {hello.Version} {hello.Hostname} imported={imported}" });
            await db.SaveChangesAsync();
            return Results.Ok(new AgentHelloReply { ServerId = server.Id, Name = server.Name, Role = server.Role, ImportedDevices = imported });
        });

        // ?since=<ревизия>&wait=<сек>: если ничего не менялось, ответ ждёт изменения (длинный опрос) —
        // новое устройство из приложения попадает на сервер за секунды, а не за полминуты.
        g.MapGet(AgentPaths.State, async (long? since, int? wait, HttpContext http, MayakDb db, ClusterService cluster, IConfiguration cfg) =>
        {
            var server = http.AgentServer();
            if (since != null && wait is > 0)
            {
                var next = ClusterService.Changes.Next;
                var rev = await db.Cluster.Where(c => c.Id == 1).Select(c => (long?)c.Revision).FirstOrDefaultAsync();
                if (rev == since)
                {
                    try { await next.WaitAsync(TimeSpan.FromSeconds(Math.Min(wait.Value, 50)), http.RequestAborted); }
                    catch (TimeoutException) { }
                }
            }
            server.LastSeen = DateTime.UtcNow;
            await db.SaveChangesAsync();
            try
            {
                var state = await cluster.StateForAsync(server, http.RequestAborted);
                // Счётчики трафика Xray по клиентам на выходах (агент 0.2+ включает их один раз, это перезапуск Xray).
                state.XrayStats = server.Role == ServerRoles.Exit && cfg.GetValue("Usage:XrayStats", true);
                return Results.Ok(state);
            }
            catch (RelayTargetUnavailableException)
            {
                // A non-success state read makes current agents keep their
                // existing relay; a successful null relay would remove it.
                return Results.Json(new { error = "relay_target_unready" }, statusCode: 503);
            }
        });

        g.MapPost(AgentPaths.Report, async (AgentReport report, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            var server = http.AgentServer();
            server.LastSeen = DateTime.UtcNow;
            server.LastError = report.Error;
            server.LastReport = JsonSerializer.Serialize(new AgentReport
            {
                AppliedRevision = report.AppliedRevision,
                Error = report.Error,
                Result = report.Result,
                ReservedIps = report.ReservedIps,
                Warnings = report.Warnings,
                DryRun = report.DryRun,
                At = DateTime.UtcNow,
                Protocol = report.Protocol,
                IdentityVersion = report.IdentityVersion,
                CredentialsRevision = report.CredentialsRevision,
                RuntimeReady = report.RuntimeReady,
                ConfigValid = report.ConfigValid,
                SelfTestPassed = report.SelfTestPassed,
                ProvisioningProof = report.ProvisioningProof,
                Host = report.Host,
                XrayStatsEnabled = report.XrayStatsEnabled,
            });
            if (server.Role == ServerRoles.Exit && string.Equals(report.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
            {
                var endpoint = await db.ExitEndpoints.FirstOrDefaultAsync(e => e.ServerId == server.Id, http.RequestAborted);
                if (endpoint != null)
                {
                    endpoint.ProtocolReportReceivedAt = DateTime.UtcNow;
                    endpoint.ReportedIdentityVersion = report.IdentityVersion;
                    endpoint.ReportedCredentialsRevision = report.CredentialsRevision;
                    endpoint.RuntimeReady = report.RuntimeReady;
                    endpoint.ConfigValid = report.ConfigValid;
                    endpoint.SelfTestPassed = report.SelfTestPassed;
                    endpoint.DryRun = report.DryRun;
                    endpoint.ProtocolError = report.Error;
                }
            }
            if (server.ProvisioningStatus is "syncing" or "installed")
            {
                var identity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, http.RequestAborted);
                var currentRevision = identity?.Revision;
                bool identityCurrent = identity != null && server.ProvisionIdentityMatched &&
                    Mayak.Api.Provisioning.ProvisioningPlanner.IdentityHashMatches(server.ProvisioningIdentityHash, identity);
                // Хэш старой формулы (с DNS и названием) переводим на новую, пока они ещё совпадают.
                if (identityCurrent) server.ProvisioningIdentityHash = Mayak.Api.Provisioning.ProvisioningPlanner.IdentityHash(identity!);
                if (!identityCurrent)
                {
                    FailProvisioning(server, "Identity изменилась или не подтверждена. Сервер оставлен неактивным.");
                }
                else if (report.DryRun || !string.IsNullOrEmpty(report.Error))
                {
                    FailProvisioning(server, "Агент сообщил о dry-run или ошибке применения. Сервер оставлен неактивным.");
                }
                else if (currentRevision == null || report.AppliedRevision > currentRevision.Value)
                {
                    FailProvisioning(server, "Агент прислал некорректное подтверждение ревизии. Сервер оставлен неактивным.");
                }
                else if (report.AppliedRevision < currentRevision.Value)
                {
                    server.ProvisioningStatus = "syncing";
                    server.ProvisioningMessage = "Агент применяет устаревшую ревизию; ожидается подтверждение текущей.";
                    server.ProvisioningConfirmedRevision = null;
                    server.ProvisioningConfirmedAt = null;
                    server.ProvisioningUpdatedAt = DateTime.UtcNow;
                }
                else if (report.ProvisioningProof is { AwgRunning: true, XrayRunning: true, ConfigurationLoaded: true, PostApplyCheckPassed: true })
                {
                    server.ProvisioningStatus = "installed";
                    server.ProvisioningMessage = "Агент подтвердил AWG/Xray, конфигурацию и актуальную ревизию. Сервер оставлен неактивным.";
                    server.ProvisioningConfirmedRevision = currentRevision.Value;
                    server.ProvisioningConfirmedAt = DateTime.UtcNow;
                    server.ProvisioningUpdatedAt = DateTime.UtcNow;
                }
                else
                {
                    FailProvisioning(server, "Агент не подтвердил работающие AWG/Xray и post-apply проверку. Сервер оставлен неактивным.");
                }
            }
            if (report.Peers.Count > 0)
            {
                var byKey = report.Peers.Where(p => p.PublicKey.Length > 0).GroupBy(p => p.PublicKey).ToDictionary(x => x.Key, x => x.First());
                var keys = byKey.Keys.ToList();
                var devices = await db.Devices.Where(d => keys.Contains(d.AwgPublicKey)).ToListAsync();
                foreach (var d in devices)
                {
                    var p = byKey[d.AwgPublicKey];
                    if (p.LatestHandshake is DateTime hs && (d.LastHandshake == null || hs > d.LastHandshake)) d.LastHandshake = DateTime.SpecifyKind(hs, DateTimeKind.Utc);
                    // Счётчики WireGuard сбрасываются при перезапуске: держим максимум за сеанс сервера.
                    d.RxBytes = Math.Max(d.RxBytes, p.RxBytes);
                    d.TxBytes = Math.Max(d.TxBytes, p.TxBytes);
                }
            }
            // История для статистики админки: объём и время в сети по часам и суткам (AWG и Xray), нагрузка сервера.
            // Отчёты пула VLESS этого не несут.
            if (!string.Equals(report.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
                await UsageRecorder.RecordAsync(db, server.Id, report, DateTime.UtcNow, http.RequestAborted);
            await db.SaveChangesAsync();
            await tx.CommitAsync(http.RequestAborted);
            return Results.NoContent();
        });
    }

    private static void FailProvisioning(Server server, string message)
    {
        server.ProvisioningStatus = "failed";
        server.ProvisioningMessage = message;
        server.ProvisioningUpdatedAt = DateTime.UtcNow;
        server.ProvisionIdentityMatched = false;
        server.ProvisioningIdentityHash = null;
        server.ProvisioningConfirmedRevision = null;
        server.ProvisioningConfirmedAt = null;
    }
}
