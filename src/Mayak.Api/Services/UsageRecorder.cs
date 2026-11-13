using Mayak.Api.Data;
using Mayak.Core.Agent;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using NpgsqlTypes;

namespace Mayak.Api.Services;

/// <summary>
/// Арифметика истории использования. Только объём и время в сети (правило 5): ни адресов, ни сайтов.
/// Сутки считаются по Москве (UTC+3, без перехода на летнее время).
/// </summary>
public static class UsageMath
{
    public const short HourSpan = 1;
    public const short DaySpan = 24;
    /// <summary>Пир «в сети», если рукопожатие было не раньше чем столько секунд назад (WireGuard обновляет его раз в 2 минуты при трафике).</summary>
    public const int OnlineWindowSeconds = 180;
    /// <summary>Больше этого промежутка между отчётами в «время в сети» не засчитывается: агент мог молчать.</summary>
    public const int MaxGapSeconds = 180;
    static readonly TimeSpan Msk = TimeSpan.FromHours(3);

    public static DateTime HourBucket(DateTime utc) => new(utc.Year, utc.Month, utc.Day, utc.Hour, 0, 0, DateTimeKind.Utc);

    /// <summary>Полночь по Москве того же дня, выраженная в UTC.</summary>
    public static DateTime DayBucket(DateTime utc)
    {
        var msk = utc + Msk;
        return new DateTime(msk.Year, msk.Month, msk.Day, 0, 0, 0, DateTimeKind.Utc) - Msk;
    }

    /// <summary>Дата суток по Москве для подписи (yyyy-MM-dd).</summary>
    public static string DayLabel(DateTime dayBucketUtc) => (dayBucketUtc + Msk).ToString("yyyy-MM-dd");

    /// <summary>
    /// Прирост счётчиков. Первый отчёт о пире — только база (0), иначе вся накопленная с запуска контейнера сумма
    /// попала бы в один час. Если счётчик уменьшился, сервер или пир перезапущен: прирост — новое значение.
    /// </summary>
    public static (long Rx, long Tx) Delta(long? prevRx, long? prevTx, long rx, long tx)
    {
        if (prevRx == null || prevTx == null) return (0, 0);
        rx = Math.Max(0, rx); tx = Math.Max(0, tx);
        if (rx < prevRx || tx < prevTx) return (rx, tx);
        return (rx - prevRx.Value, tx - prevTx.Value);
    }

    public static bool IsOnline(DateTime? handshake, DateTime now) =>
        handshake is DateTime hs && hs <= now.AddMinutes(1) && (now - hs).TotalSeconds <= OnlineWindowSeconds;

    public static int OnlineSeconds(DateTime? previousReportAt, DateTime now, bool online)
    {
        if (!online || previousReportAt is not DateTime prev) return 0;
        var gap = (now - prev).TotalSeconds;
        return gap <= 0 ? 0 : (int)Math.Min(gap, MaxGapSeconds);
    }
}

/// <summary>Запись прироста из отчёта агента в историю (часы и сутки) — в той же транзакции, что и отчёт.</summary>
public static class UsageRecorder
{
    public static async Task RecordAsync(MayakDb db, Guid serverId, IReadOnlyCollection<AgentPeerStats> peers, DateTime now, CancellationToken ct = default)
    {
        var byKey = peers.Where(p => p.PublicKey.Length is > 0 and <= 64)
            .GroupBy(p => p.PublicKey).ToDictionary(g => g.Key, g => g.First());
        var counters = await db.PeerCounters.Where(c => c.ServerId == serverId).ToDictionaryAsync(c => c.PublicKey, ct);
        var keys = byKey.Keys.ToList();
        var deviceByKey = keys.Count == 0 ? new Dictionary<string, Guid>() :
            (await db.Devices.AsNoTracking().Where(d => keys.Contains(d.AwgPublicKey)).Select(d => new { d.Id, d.AwgPublicKey }).ToListAsync(ct))
            .GroupBy(d => d.AwgPublicKey).ToDictionary(g => g.Key, g => g.First().Id);

        long serverRx = 0, serverTx = 0, peerSeconds = 0;
        var onlinePeers = 0;
        var devIds = new List<Guid>(); var devRx = new List<long>(); var devTx = new List<long>(); var devSec = new List<int>();
        foreach (var (key, p) in byKey)
        {
            counters.TryGetValue(key, out var prev);
            var (rx, tx) = UsageMath.Delta(prev?.RxBytes, prev?.TxBytes, p.RxBytes, p.TxBytes);
            var hs = p.LatestHandshake is DateTime h ? DateTime.SpecifyKind(h, DateTimeKind.Utc) : (DateTime?)null;
            var online = UsageMath.IsOnline(hs, now);
            var seconds = UsageMath.OnlineSeconds(prev?.At, now, online);
            if (prev == null)
            {
                prev = new PeerCounter { ServerId = serverId, PublicKey = key };
                db.PeerCounters.Add(prev);
            }
            prev.RxBytes = Math.Max(0, p.RxBytes);
            prev.TxBytes = Math.Max(0, p.TxBytes);
            prev.LastHandshake = hs ?? prev.LastHandshake;
            prev.At = now;

            serverRx += rx; serverTx += tx; peerSeconds += seconds;
            if (online) onlinePeers++;
            if ((rx > 0 || tx > 0 || seconds > 0) && deviceByKey.TryGetValue(key, out var deviceId))
            {
                devIds.Add(deviceId); devRx.Add(rx); devTx.Add(tx); devSec.Add(seconds);
            }
        }

        var hour = UsageMath.HourBucket(now);
        var day = UsageMath.DayBucket(now);
        if (devIds.Count > 0)
        {
            await db.Database.ExecuteSqlRawAsync("""
                INSERT INTO "DeviceUsage" ("DeviceId","ServerId","Span","Bucket","RxBytes","TxBytes","OnlineSeconds")
                SELECT u.d, @server, s.span, s.bucket, u.rx, u.tx, u.sec
                FROM unnest(@devs, @rxs, @txs, @secs) AS u(d, rx, tx, sec)
                CROSS JOIN (VALUES (@hourSpan, @hour), (@daySpan, @day)) AS s(span, bucket)
                ON CONFLICT ("DeviceId","ServerId","Span","Bucket") DO UPDATE SET
                  "RxBytes" = "DeviceUsage"."RxBytes" + EXCLUDED."RxBytes",
                  "TxBytes" = "DeviceUsage"."TxBytes" + EXCLUDED."TxBytes",
                  "OnlineSeconds" = "DeviceUsage"."OnlineSeconds" + EXCLUDED."OnlineSeconds"
                """,
                [
                    new NpgsqlParameter("server", NpgsqlDbType.Uuid) { Value = serverId },
                    new NpgsqlParameter("devs", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = devIds.ToArray() },
                    new NpgsqlParameter("rxs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = devRx.ToArray() },
                    new NpgsqlParameter("txs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = devTx.ToArray() },
                    new NpgsqlParameter("secs", NpgsqlDbType.Array | NpgsqlDbType.Integer) { Value = devSec.ToArray() },
                    new NpgsqlParameter("hourSpan", NpgsqlDbType.Smallint) { Value = UsageMath.HourSpan },
                    new NpgsqlParameter("daySpan", NpgsqlDbType.Smallint) { Value = UsageMath.DaySpan },
                    new NpgsqlParameter("hour", NpgsqlDbType.TimestampTz) { Value = hour },
                    new NpgsqlParameter("day", NpgsqlDbType.TimestampTz) { Value = day },
                ], ct);
        }

        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO "ServerUsage" ("ServerId","Span","Bucket","RxBytes","TxBytes","PeakPeers","PeerSeconds","Reports")
            VALUES (@server, @hourSpan, @hour, @rx, @tx, @peak, @psec, 1), (@server, @daySpan, @day, @rx, @tx, @peak, @psec, 1)
            ON CONFLICT ("ServerId","Span","Bucket") DO UPDATE SET
              "RxBytes" = "ServerUsage"."RxBytes" + EXCLUDED."RxBytes",
              "TxBytes" = "ServerUsage"."TxBytes" + EXCLUDED."TxBytes",
              "PeakPeers" = GREATEST("ServerUsage"."PeakPeers", EXCLUDED."PeakPeers"),
              "PeerSeconds" = "ServerUsage"."PeerSeconds" + EXCLUDED."PeerSeconds",
              "Reports" = "ServerUsage"."Reports" + 1
            """,
            [
                new NpgsqlParameter("server", NpgsqlDbType.Uuid) { Value = serverId },
                new NpgsqlParameter("hourSpan", NpgsqlDbType.Smallint) { Value = UsageMath.HourSpan },
                new NpgsqlParameter("daySpan", NpgsqlDbType.Smallint) { Value = UsageMath.DaySpan },
                new NpgsqlParameter("hour", NpgsqlDbType.TimestampTz) { Value = hour },
                new NpgsqlParameter("day", NpgsqlDbType.TimestampTz) { Value = day },
                new NpgsqlParameter("rx", NpgsqlDbType.Bigint) { Value = serverRx },
                new NpgsqlParameter("tx", NpgsqlDbType.Bigint) { Value = serverTx },
                new NpgsqlParameter("peak", NpgsqlDbType.Integer) { Value = onlinePeers },
                new NpgsqlParameter("psec", NpgsqlDbType.Bigint) { Value = peerSeconds },
            ], ct);
    }

    /// <summary>Сроки хранения: часы — Usage:HourlyDays (14), сутки — Usage:DailyDays (366), счётчики — 2 дня без отчётов.</summary>
    public static async Task<int> PruneAsync(MayakDb db, DateTime now, int hourlyDays, int dailyDays, CancellationToken ct = default)
    {
        var hourFrom = now.AddDays(-hourlyDays);
        var dayFrom = now.AddDays(-dailyDays);
        var counterFrom = now.AddDays(-2);
        var n = await db.DeviceUsage.Where(u => u.Span == UsageMath.HourSpan && u.Bucket < hourFrom).ExecuteDeleteAsync(ct);
        n += await db.DeviceUsage.Where(u => u.Span == UsageMath.DaySpan && u.Bucket < dayFrom).ExecuteDeleteAsync(ct);
        n += await db.ServerUsage.Where(u => u.Span == UsageMath.HourSpan && u.Bucket < hourFrom).ExecuteDeleteAsync(ct);
        n += await db.ServerUsage.Where(u => u.Span == UsageMath.DaySpan && u.Bucket < dayFrom).ExecuteDeleteAsync(ct);
        n += await db.PeerCounters.Where(c => c.At < counterFrom).ExecuteDeleteAsync(ct);
        return n;
    }
}

/// <summary>Раз в час удаляет историю старше срока хранения (политика конфиденциальности: 14 дней по часам, 1 год по дням).</summary>
public sealed class UsageRetentionService(IServiceScopeFactory scopes, IConfiguration cfg, ILogger<UsageRetentionService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(2), stop); } catch (OperationCanceledException) { return; }
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
                var n = await UsageRecorder.PruneAsync(db, DateTime.UtcNow,
                    Math.Clamp(cfg.GetValue("Usage:HourlyDays", 14), 1, 60), Math.Clamp(cfg.GetValue("Usage:DailyDays", 366), 7, 1100), stop);
                if (n > 0) log.LogInformation("Удалено записей истории использования: {Count}", n);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (Exception e) { log.LogWarning("Очистка истории использования не удалась: {Type}", e.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromHours(1), stop); } catch (OperationCanceledException) { return; }
        }
    }
}
