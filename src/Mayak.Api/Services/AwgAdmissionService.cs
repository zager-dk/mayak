using System.Net;
using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

/// <summary>Cooperative native-client allocations across approved shared-AWG exits.</summary>
public sealed class AwgAdmissionService(MayakDb db)
{
    public sealed record Candidate(Guid Id, string Host, int Port, bool Preferred, string[] ExpectedEgressIps);

    public async Task<IReadOnlyList<Candidate>> CandidatesAsync(Device device, ClusterIdentity cluster, CancellationToken ct,
        bool includeFull = false, bool lockHeld = false, Guid? boundServerId = null)
    {
        await using var cleanupTx = lockHeld ? null : await db.Database.BeginTransactionAsync(ct);
        if (cleanupTx != null)
        {
            await ProvisioningGuards.AcquireHostMutationLockAsync(db, ct);
            await DeviceWriteLock.AcquireAsync(db, ct);
        }
        await ReleaseInactiveAsync(ct);
        var now = DateTime.UtcNow;
        var servers = await db.Servers.AsNoTracking().Where(s => s.Role == ServerRoles.Exit && s.AutoSelectEnabled)
            .OrderByDescending(s => s.Active).ThenBy(s => s.Id).ToListAsync(ct);
        var counts = await db.AwgAllocations.Where(a => a.ReleasedAt == null).GroupBy(a => a.ServerId)
            .Select(g => new { Id = g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Id, x => x.Count, ct);
        var legacy = await db.Devices.CountAsync(d => d.Enabled && !d.AutoConnectManaged && d.ServiceProtocol != "vless" && d.Account != null && d.Account.Enabled &&
            (d.Account.PaidUntil == null || d.Account.PaidUntil > now), ct);
        var identity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
        var canonicalHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var choices = new List<Candidate>();
        foreach (var server in servers)
        {
            var hostKey = ProvisioningGuards.CanonicalHostKey(server.Host);
            if (!canonicalHosts.Add(hostKey) || await ProvisioningGuards.HostExistsAsync(db, server.Host, server.Id, ct)) continue;
            if (!ProvisioningGuards.IsReady(server, identity, now) || identity?.Revision != cluster.Revision) continue;
            if (!TryExpectedIps(server.ExpectedEgressIpsJson, out var ips) || ips.Length == 0) continue;
            if (string.IsNullOrWhiteSpace(server.Host) || server.Host.Contains('/') || server.Host.Contains(' ')) continue;
            var hasAllocation = await db.AwgAllocations.AnyAsync(a => a.DeviceId == device.Id && a.ServerId == server.Id && a.ReleasedAt == null, ct);
            if (!includeFull && !hasAllocation && counts.GetValueOrDefault(server.Id) + legacy >= server.NativeCapacity) continue;
            choices.Add(new(server.Id, server.Host, ClusterService.AwgOf(cluster).Port, server.Active, ips));
        }
        var byId = servers.ToDictionary(s => s.Id);
        var ordered = choices.OrderByDescending(x => x.Preferred)
            .ThenBy(x => (double)counts.GetValueOrDefault(x.Id) / byId[x.Id].NativeCapacity).ThenBy(x => x.Id);
        var result = boundServerId is Guid target
            ? ordered.Where(x => x.Id == target).Take(1).ToArray()
            : ordered.Take(3).ToArray();
        if (cleanupTx != null) await cleanupTx.CommitAsync(ct);
        return result;
    }

    public async Task<(string? Code, AwgAllocation? Allocation, string? Host)> AcquireAsync(Account account, Device device,
        string expectedAppKey, string installationId, string publicKey, Guid serverId, string attemptId, ClusterIdentity cluster, CancellationToken ct)
    {
        if (!IsValidAttemptId(attemptId)) return ("INVALID_REQUEST", null, null);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await ProvisioningGuards.AcquireHostMutationLockAsync(db, ct);
        await DeviceWriteLock.AcquireAsync(db, ct); // Lock order: host set, shared device lock, then account/device/server/allocation rows.
        await ReleaseInactiveAsync(ct);
        await db.Entry(account).ReloadAsync(ct);
        if (db.Entry(account).State == EntityState.Detached) return ("REVOKED", null, null);
        await db.Entry(device).ReloadAsync(ct);
        if (db.Entry(device).State == EntityState.Detached) return ("REVOKED", null, null);
        await db.Entry(cluster).ReloadAsync(ct);
        if (!DeviceAccess.KeyAuthorizes(account, device, expectedAppKey)) return ("REVOKED", null, null);
        if (!account.IsActive(DateTime.UtcNow)) return ("ACCOUNT_EXPIRED", null, null);
        if (!device.Enabled || device.AccountId != account.Id || device.InstallationId != installationId ||
            device.AwgPublicKey != publicKey || !device.AutoConnectManaged) return ("REVOKED", null, null);
        var old = await db.AwgAllocations.FirstOrDefaultAsync(a => a.DeviceId == device.Id && a.AttemptId == attemptId, ct);
        if (old != null)
        {
            if (old.ReleasedAt != null) return ("INVALID_REQUEST", null, null);
            if (old.ServerId != serverId) return ("INVALID_REQUEST", null, null);
            var stillEligible = (await CandidatesAsync(device, cluster, ct, includeFull: true, lockHeld: true, boundServerId: old.ServerId)).SingleOrDefault();
            if (stillEligible == null) return ("NOT_READY", null, null);
            await tx.CommitAsync(ct);
            return (null, old, stillEligible.Host);
        }
        if (await db.AwgAllocations.AnyAsync(a => a.DeviceId == device.Id && a.ReleasedAt == null, ct))
            return ("INVALID_REQUEST", null, null);
        // Validate the selected exit independently of the three-item advertisement limit.
        var candidate = (await CandidatesAsync(device, cluster, ct, includeFull: true, lockHeld: true, boundServerId: serverId)).SingleOrDefault();
        if (candidate == null) return ("NOT_READY", null, null);
        var server = await db.Servers.FirstAsync(s => s.Id == serverId, ct);
        var used = await db.AwgAllocations.CountAsync(a => a.ServerId == serverId && a.ReleasedAt == null, ct);
        var legacy = await db.Devices.CountAsync(d => d.Enabled && !d.AutoConnectManaged && d.ServiceProtocol != "vless" && d.Account != null && d.Account.Enabled &&
            (d.Account.PaidUntil == null || d.Account.PaidUntil > DateTime.UtcNow), ct);
        if (used + legacy >= server.NativeCapacity) return ("FULL", null, null);
        var allocation = new AwgAllocation { DeviceId = device.Id, ServerId = serverId, AttemptId = attemptId, AuthKeyHash = Tokens.Hash(expectedAppKey) };
        db.AwgAllocations.Add(allocation);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return (null, allocation, candidate.Host);
    }

    public Task<(string? Code, AwgAllocation? Allocation, string? Host)> AcquireAsync(Account account, Device device,
        Guid serverId, string attemptId, ClusterIdentity cluster, CancellationToken ct) =>
        AcquireAsync(account, device, account.AppKey ?? "", device.InstallationId ?? "", device.AwgPublicKey,
            serverId, attemptId, cluster, ct);

    public async Task<(bool Authorized, bool Updated)> SetAllocationAsync(Account account, Device device, string expectedAppKey,
        string installationId, string publicKey, Guid allocationId, string attemptId, string action, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DeviceWriteLock.AcquireAsync(db, ct);
        await db.Entry(account).ReloadAsync(ct);
        if (db.Entry(account).State == EntityState.Detached) return (false, false);
        await db.Entry(device).ReloadAsync(ct);
        if (db.Entry(device).State == EntityState.Detached) return (false, false);
        var keyOk = action == "proven"
            ? DeviceAccess.KeyAuthorizes(account, device, expectedAppKey)
            : await CleanupKeyAuthorizesAsync(account, device, expectedAppKey, attemptId, ct);
        if (!account.IsActive(DateTime.UtcNow) || !keyOk ||
            device.AccountId != account.Id || device.InstallationId != installationId || device.AwgPublicKey != publicKey ||
            !device.AutoConnectManaged || action == "proven" && !device.Enabled)
            return (false, false);
        var allocation = await db.AwgAllocations.FirstOrDefaultAsync(a => a.Id == allocationId && a.DeviceId == device.Id && a.AttemptId == attemptId, ct);
        if (allocation != null)
        {
            if (action == "proven") allocation.ProvenAt = DateTime.UtcNow;
            else allocation.ReleasedAt ??= DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
        }
        await tx.CommitAsync(ct);
        return (true, allocation != null);
    }

    public async Task<bool> ReconcileAsync(Account account, Device device, string expectedAppKey, string installationId, string publicKey,
        string attemptId, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DeviceWriteLock.AcquireAsync(db, ct);
        await db.Entry(account).ReloadAsync(ct);
        if (db.Entry(account).State == EntityState.Detached) return false;
        await db.Entry(device).ReloadAsync(ct);
        if (db.Entry(device).State == EntityState.Detached) return false;
        if (!account.IsActive(DateTime.UtcNow) || !await CleanupKeyAuthorizesAsync(account, device, expectedAppKey, attemptId, ct) ||
            device.AccountId != account.Id || device.InstallationId != installationId || device.AwgPublicKey != publicKey || !device.AutoConnectManaged)
            return false;
        await db.AwgAllocations.Where(a => a.DeviceId == device.Id && a.AttemptId == attemptId && a.ReleasedAt == null)
            .ExecuteUpdateAsync(u => u.SetProperty(a => a.ReleasedAt, DateTime.UtcNow), ct);
        await tx.CommitAsync(ct);
        return true;
    }

    /// <summary>
    /// Ключ для release/reconcile: текущий, предыдущий ключ установки или ровно тот ключ, которым открыта эта попытка.
    /// Освобождение места безвредно, а без этого смена ключа при включённом VPN оставляла бы попытку, которую нельзя закрыть.
    /// </summary>
    private async Task<bool> CleanupKeyAuthorizesAsync(Account account, Device device, string expectedAppKey, string attemptId, CancellationToken ct)
    {
        if (DeviceAccess.CleanupAuthorizes(account, device, expectedAppKey)) return true;
        if (device.AccountId != account.Id || string.IsNullOrEmpty(expectedAppKey)) return false;
        var hash = Tokens.Hash(expectedAppKey);
        // Места, открытые до появления AuthKeyHash (старые клиенты), открыты ключом аккаунта: его и принимаем.
        var accountKey = account.AppKey != null && string.Equals(account.AppKey, expectedAppKey, StringComparison.Ordinal);
        return await db.AwgAllocations.AnyAsync(a => a.DeviceId == device.Id && a.AttemptId == attemptId &&
            (a.AuthKeyHash == hash || accountKey && a.AuthKeyHash == null), ct);
    }

    private Task<int> ReleaseInactiveAsync(CancellationToken ct) => db.AwgAllocations
        .Where(a => a.ReleasedAt == null && db.Devices.Any(d => d.Id == a.DeviceId &&
            (!d.Enabled || !d.Account!.Enabled || (d.Account.PaidUntil != null && d.Account.PaidUntil <= DateTime.UtcNow))))
        .ExecuteUpdateAsync(u => u.SetProperty(a => a.ReleasedAt, DateTime.UtcNow), ct);

    public static bool TryExpectedIps(string json, out string[] ips)
    {
        ips = Array.Empty<string>();
        try
        {
            var values = JsonSerializer.Deserialize<string[]>(json) ?? Array.Empty<string>();
            var normalized = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var value in values)
            {
                if (!ProvisioningRules.TryPublicIpv4(value, null, out var ip, out _)) return false;
                normalized.Add(ip);
            }
            ips = normalized.ToArray();
            return true;
        }
        catch (JsonException) { return false; }
    }

    public static bool IsValidAttemptId(string value) => value.Length is >= 16 and <= 128 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
