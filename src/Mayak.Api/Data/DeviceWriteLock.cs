using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Data;

/// <summary>Cross-process serialization for device count and address allocation.</summary>
public static class DeviceWriteLock
{
    public static Task AcquireAsync(MayakDb db, CancellationToken ct) =>
        db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(742019, 1)", ct);

    public static async Task EnsureRoomAsync(MayakDb db, Account account, CancellationToken ct)
    {
        var count = await db.Devices.CountAsync(d => d.AccountId == account.Id, ct);
        if (count >= account.MaxDevices)
            throw new DeviceLimitException(account.MaxDevices);
    }
}

public sealed class DeviceLimitException(int maximum) : InvalidOperationException($"Можно не больше {maximum} устройств. Удалите ненужное.");
