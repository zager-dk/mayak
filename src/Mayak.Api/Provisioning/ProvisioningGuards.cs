using System.Net;
using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Core.Agent;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Provisioning;

public static class ProvisioningGuards
{
    public static string CanonicalHostKey(string value)
    {
        var host = value.Trim().TrimEnd('.');
        if (!IPAddress.TryParse(host, out var ip)) return host.ToLowerInvariant();
        // The socket endpoint is IPv4 even when supplied in mapped IPv6 form.
        // Normalize old rows as well as new input before uniqueness checks.
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString().ToLowerInvariant();
    }

    public static async Task<bool> HostExistsAsync(MayakDb db, string host, Guid? exceptId, CancellationToken ct)
    {
        var key = CanonicalHostKey(host);
        var existing = await db.Servers.AsNoTracking().Where(s => exceptId == null || s.Id != exceptId)
            .Select(s => s.Host).ToListAsync(ct);
        return existing.Any(h => CanonicalHostKey(h) == key);
    }

    public static async Task AcquireHostMutationLockAsync(MayakDb db, CancellationToken ct) =>
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(742019, 3)", ct);

    public static bool IsReady(Server server, ClusterIdentity? cluster, DateTime now)
    {
        if (cluster == null || server.ProvisioningStatus != "installed" || !server.ProvisionIdentityMatched ||
            !ProvisioningPlanner.IdentityHashMatches(server.ProvisioningIdentityHash, cluster) ||
            server.ProvisioningConfirmedRevision != cluster.Revision || server.ProvisioningConfirmedAt is not DateTime confirmedAt ||
            server.LastSeen is not DateTime lastSeen || !Fresh(confirmedAt, now) || !Fresh(lastSeen, now) ||
            !string.IsNullOrEmpty(server.LastError) || string.IsNullOrWhiteSpace(server.LastReport)) return false;
        try
        {
            var report = JsonSerializer.Deserialize<AgentReport>(server.LastReport);
            var proof = report?.ProvisioningProof;
            return report != null && report.Error == null && !report.DryRun && report.AppliedRevision == cluster.Revision &&
                   proof is { AwgRunning: true, XrayRunning: true, ConfigurationLoaded: true, PostApplyCheckPassed: true };
        }
        catch (JsonException) { return false; }
    }

    private static bool Fresh(DateTime value, DateTime now) => value <= now.AddSeconds(5) && value >= now.AddMinutes(-2);
}
