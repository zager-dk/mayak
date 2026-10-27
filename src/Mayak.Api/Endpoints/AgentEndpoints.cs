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
            if (server.Role == ServerRoles.Exit && hello.Identity != null)
            {
                if (await cluster.AdoptIdentityAsync(hello.Identity, http.RequestAborted))
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

        g.MapGet(AgentPaths.State, async (HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var server = http.AgentServer();
            server.LastSeen = DateTime.UtcNow;
            await db.SaveChangesAsync();
            return Results.Ok(await cluster.StateForAsync(server, http.RequestAborted));
        });

        g.MapPost(AgentPaths.Report, async (AgentReport report, HttpContext http, MayakDb db) =>
        {
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
            });
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
            await db.SaveChangesAsync();
            return Results.NoContent();
        });
    }
}
