using Mayak.Api.Data;
using Mayak.Core.Agent;
using Mayak.Core.Xray;
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
    /// <summary>Ключи служебных счётчиков в PeerCounters рядом с ключами пиров AWG (base64, 44 символа).</summary>
    public const string XrayKeyPrefix = "xray:";
    public const string NetKeyPrefix = "host:net:";

    public static string XrayKey(Guid deviceId) => XrayKeyPrefix + deviceId.ToString("N");

    /// <summary>Устройство по email клиента Xray «mayak:&lt;id без дефисов&gt;».</summary>
    public static Guid? DeviceFromXrayEmail(string email) =>
        email.StartsWith(XrayConfig.MayakEmailPrefix, StringComparison.Ordinal) &&
        Guid.TryParseExact(email[XrayConfig.MayakEmailPrefix.Length..], "N", out var id) ? id : null;

    public static Task RecordAsync(MayakDb db, Guid serverId, IReadOnlyCollection<AgentPeerStats> peers, DateTime now, CancellationToken ct = default) =>
        RecordAsync(db, serverId, new AgentReport { Peers = peers.ToList() }, now, ct);

    sealed class DeviceDelta { public long Rx, Tx, XRx, XTx; public int Sec; }

    public static async Task RecordAsync(MayakDb db, Guid serverId, AgentReport report, DateTime now, CancellationToken ct = default)
    {
        var byKey = report.Peers.Where(p => p.PublicKey.Length is > 0 and <= 64 && !p.PublicKey.Contains(':'))
            .GroupBy(p => p.PublicKey).ToDictionary(g => g.Key, g => g.First());
        var counters = await db.PeerCounters.Where(c => c.ServerId == serverId).ToDictionaryAsync(c => c.PublicKey, ct);
        var keys = byKey.Keys.ToList();
        var deviceByKey = keys.Count == 0 ? new Dictionary<string, Guid>() :
            (await db.Devices.AsNoTracking().Where(d => keys.Contains(d.AwgPublicKey)).Select(d => new { d.Id, d.AwgPublicKey }).ToListAsync(ct))
            .GroupBy(d => d.AwgPublicKey).ToDictionary(g => g.Key, g => g.First().Id);

        PeerCounter Counter(string key)
        {
            if (!counters.TryGetValue(key, out var c))
            {
                c = new PeerCounter { ServerId = serverId, PublicKey = key };
                db.PeerCounters.Add(c);
                counters[key] = c;
            }
            return c;
        }

        DeviceDelta Dev(Dictionary<Guid, DeviceDelta> map, Guid id) => map.TryGetValue(id, out var e) ? e : map[id] = new DeviceDelta();

        long serverRx = 0, serverTx = 0, xrayRx = 0, xrayTx = 0, peerSeconds = 0;
        var onlinePeers = 0;
        var perDevice = new Dictionary<Guid, DeviceDelta>();
        foreach (var (key, p) in byKey)
        {
            counters.TryGetValue(key, out var prev);
            var (rx, tx) = UsageMath.Delta(prev?.RxBytes, prev?.TxBytes, p.RxBytes, p.TxBytes);
            var hs = p.LatestHandshake is DateTime h ? DateTime.SpecifyKind(h, DateTimeKind.Utc) : (DateTime?)null;
            var online = UsageMath.IsOnline(hs, now);
            var seconds = UsageMath.OnlineSeconds(prev?.At, now, online);
            var c = Counter(key);
            c.RxBytes = Math.Max(0, p.RxBytes);
            c.TxBytes = Math.Max(0, p.TxBytes);
            c.LastHandshake = hs ?? c.LastHandshake;
            c.At = now;

            serverRx += rx; serverTx += tx; peerSeconds += seconds;
            if (online) onlinePeers++;
            if ((rx > 0 || tx > 0 || seconds > 0) && deviceByKey.TryGetValue(key, out var deviceId))
            {
                var d = Dev(perDevice, deviceId);
                d.Rx += rx; d.Tx += tx; d.Sec = Math.Max(d.Sec, seconds);
            }
        }

        // Xray: uplink — от пользователя (Rx сервера), downlink — к пользователю (Tx). «В сети» — был трафик с прошлого отчёта.
        // Время в сети устройства за отчёт из двух протоколов не складывается: берётся большее.
        if (report.XrayStatsEnabled)
        {
            var xray = report.XrayUsers.Select(u => (Id: DeviceFromXrayEmail(u.Email), u))
                .Where(x => x.Id != null).GroupBy(x => x.Id!.Value).ToDictionary(g => g.Key, g => g.First().u);
            var ids = xray.Keys.ToList();
            var known = ids.Count == 0 ? new HashSet<Guid>() :
                (await db.Devices.AsNoTracking().Where(d => ids.Contains(d.Id)).Select(d => d.Id).ToListAsync(ct)).ToHashSet();
            foreach (var (deviceId, u) in xray)
            {
                if (!known.Contains(deviceId)) continue;
                var key = XrayKey(deviceId);
                counters.TryGetValue(key, out var prev);
                var (rx, tx) = UsageMath.Delta(prev?.RxBytes, prev?.TxBytes, u.UplinkBytes, u.DownlinkBytes);
                var online = rx + tx > 0;
                var seconds = UsageMath.OnlineSeconds(prev?.At, now, online);
                var c = Counter(key);
                c.RxBytes = Math.Max(0, u.UplinkBytes);
                c.TxBytes = Math.Max(0, u.DownlinkBytes);
                if (online) c.LastHandshake = now;
                c.At = now;

                serverRx += rx; serverTx += tx; xrayRx += rx; xrayTx += tx; peerSeconds += seconds;
                if (online) onlinePeers++;
                if (rx > 0 || tx > 0 || seconds > 0)
                {
                    var d = Dev(perDevice, deviceId);
                    d.Rx += rx; d.Tx += tx; d.XRx += rx; d.XTx += tx; d.Sec = Math.Max(d.Sec, seconds);
                }
            }
        }

        // Нагрузка: процессор (среднее и максимум), память, load, диск, байты сетевого интерфейса.
        var host = report.Host;
        long netRx = 0, netTx = 0;
        if (host is { NetInterface.Length: > 0 and <= 40 })
        {
            var key = NetKeyPrefix + host.NetInterface;
            counters.TryGetValue(key, out var prev);
            (netRx, netTx) = UsageMath.Delta(prev?.RxBytes, prev?.TxBytes, host.NetRxBytes, host.NetTxBytes);
            var c = Counter(key);
            c.RxBytes = Math.Max(0, host.NetRxBytes);
            c.TxBytes = Math.Max(0, host.NetTxBytes);
            c.At = now;
        }
        double? cpu = host?.CpuPercent is double cp && double.IsFinite(cp) ? Math.Clamp(cp, 0, 100) : null;
        var memTotal = Math.Max(0, host?.MemTotalBytes ?? 0);
        var memUsed = memTotal > 0 ? Math.Clamp(memTotal - Math.Max(0, host!.MemAvailableBytes), 0, memTotal) : 0;
        var load1 = host != null && double.IsFinite(host.Load1) ? Math.Clamp(host.Load1, 0, 10000) : 0;
        var diskTotal = Math.Max(0, host?.DiskTotalBytes ?? 0);
        var diskFree = Math.Clamp(host?.DiskFreeBytes ?? 0, 0, diskTotal);

        var hour = UsageMath.HourBucket(now);
        var day = UsageMath.DayBucket(now);
        if (perDevice.Count > 0)
        {
            var list = perDevice.ToList();
            await db.Database.ExecuteSqlRawAsync("""
                INSERT INTO "DeviceUsage" ("DeviceId","ServerId","Span","Bucket","RxBytes","TxBytes","OnlineSeconds","XrayRxBytes","XrayTxBytes")
                SELECT u.d, @server, s.span, s.bucket, u.rx, u.tx, u.sec, u.xrx, u.xtx
                FROM unnest(@devs, @rxs, @txs, @secs, @xrxs, @xtxs) AS u(d, rx, tx, sec, xrx, xtx)
                CROSS JOIN (VALUES (@hourSpan, @hour), (@daySpan, @day)) AS s(span, bucket)
                ON CONFLICT ("DeviceId","ServerId","Span","Bucket") DO UPDATE SET
                  "RxBytes" = "DeviceUsage"."RxBytes" + EXCLUDED."RxBytes",
                  "TxBytes" = "DeviceUsage"."TxBytes" + EXCLUDED."TxBytes",
                  "OnlineSeconds" = "DeviceUsage"."OnlineSeconds" + EXCLUDED."OnlineSeconds",
                  "XrayRxBytes" = "DeviceUsage"."XrayRxBytes" + EXCLUDED."XrayRxBytes",
                  "XrayTxBytes" = "DeviceUsage"."XrayTxBytes" + EXCLUDED."XrayTxBytes"
                """,
                [
                    new NpgsqlParameter("server", NpgsqlDbType.Uuid) { Value = serverId },
                    new NpgsqlParameter("devs", NpgsqlDbType.Array | NpgsqlDbType.Uuid) { Value = list.Select(x => x.Key).ToArray() },
                    new NpgsqlParameter("rxs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = list.Select(x => x.Value.Rx).ToArray() },
                    new NpgsqlParameter("txs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = list.Select(x => x.Value.Tx).ToArray() },
                    new NpgsqlParameter("secs", NpgsqlDbType.Array | NpgsqlDbType.Integer) { Value = list.Select(x => x.Value.Sec).ToArray() },
                    new NpgsqlParameter("xrxs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = list.Select(x => x.Value.XRx).ToArray() },
                    new NpgsqlParameter("xtxs", NpgsqlDbType.Array | NpgsqlDbType.Bigint) { Value = list.Select(x => x.Value.XTx).ToArray() },
                    new NpgsqlParameter("hourSpan", NpgsqlDbType.Smallint) { Value = UsageMath.HourSpan },
                    new NpgsqlParameter("daySpan", NpgsqlDbType.Smallint) { Value = UsageMath.DaySpan },
                    new NpgsqlParameter("hour", NpgsqlDbType.TimestampTz) { Value = hour },
                    new NpgsqlParameter("day", NpgsqlDbType.TimestampTz) { Value = day },
                ], ct);
        }

        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO "ServerUsage" ("ServerId","Span","Bucket","RxBytes","TxBytes","PeakPeers","PeerSeconds","Reports",
              "XrayRxBytes","XrayTxBytes","CpuSamples","CpuSum","CpuMax","Load1Max","MemUsedMax","MemTotal","NetRxBytes","NetTxBytes","DiskFree","DiskTotal")
            SELECT @server, s.span, s.bucket, @rx, @tx, @peak, @psec, 1,
              @xrx, @xtx, @cpun, @cpu, @cpu, @load, @memUsed, @memTotal, @netRx, @netTx, @diskFree, @diskTotal
            FROM (VALUES (@hourSpan, @hour), (@daySpan, @day)) AS s(span, bucket)
            ON CONFLICT ("ServerId","Span","Bucket") DO UPDATE SET
              "RxBytes" = "ServerUsage"."RxBytes" + EXCLUDED."RxBytes",
              "TxBytes" = "ServerUsage"."TxBytes" + EXCLUDED."TxBytes",
              "PeakPeers" = GREATEST("ServerUsage"."PeakPeers", EXCLUDED."PeakPeers"),
              "PeerSeconds" = "ServerUsage"."PeerSeconds" + EXCLUDED."PeerSeconds",
              "Reports" = "ServerUsage"."Reports" + 1,
              "XrayRxBytes" = "ServerUsage"."XrayRxBytes" + EXCLUDED."XrayRxBytes",
              "XrayTxBytes" = "ServerUsage"."XrayTxBytes" + EXCLUDED."XrayTxBytes",
              "CpuSamples" = "ServerUsage"."CpuSamples" + EXCLUDED."CpuSamples",
              "CpuSum" = "ServerUsage"."CpuSum" + EXCLUDED."CpuSum",
              "CpuMax" = GREATEST("ServerUsage"."CpuMax", EXCLUDED."CpuMax"),
              "Load1Max" = GREATEST("ServerUsage"."Load1Max", EXCLUDED."Load1Max"),
              "MemUsedMax" = GREATEST("ServerUsage"."MemUsedMax", EXCLUDED."MemUsedMax"),
              "MemTotal" = CASE WHEN EXCLUDED."MemTotal" > 0 THEN EXCLUDED."MemTotal" ELSE "ServerUsage"."MemTotal" END,
              "NetRxBytes" = "ServerUsage"."NetRxBytes" + EXCLUDED."NetRxBytes",
              "NetTxBytes" = "ServerUsage"."NetTxBytes" + EXCLUDED."NetTxBytes",
              "DiskFree" = CASE WHEN EXCLUDED."DiskTotal" > 0 THEN EXCLUDED."DiskFree" ELSE "ServerUsage"."DiskFree" END,
              "DiskTotal" = CASE WHEN EXCLUDED."DiskTotal" > 0 THEN EXCLUDED."DiskTotal" ELSE "ServerUsage"."DiskTotal" END
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
                new NpgsqlParameter("xrx", NpgsqlDbType.Bigint) { Value = xrayRx },
                new NpgsqlParameter("xtx", NpgsqlDbType.Bigint) { Value = xrayTx },
                new NpgsqlParameter("cpun", NpgsqlDbType.Integer) { Value = cpu == null ? 0 : 1 },
                new NpgsqlParameter("cpu", NpgsqlDbType.Double) { Value = cpu ?? 0 },
                new NpgsqlParameter("load", NpgsqlDbType.Double) { Value = load1 },
                new NpgsqlParameter("memUsed", NpgsqlDbType.Bigint) { Value = memUsed },
                new NpgsqlParameter("memTotal", NpgsqlDbType.Bigint) { Value = memTotal },
                new NpgsqlParameter("netRx", NpgsqlDbType.Bigint) { Value = netRx },
                new NpgsqlParameter("netTx", NpgsqlDbType.Bigint) { Value = netTx },
                new NpgsqlParameter("diskFree", NpgsqlDbType.Bigint) { Value = diskFree },
                new NpgsqlParameter("diskTotal", NpgsqlDbType.Bigint) { Value = diskTotal },
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
