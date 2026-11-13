using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

/// <summary>
/// Статистика для админки: сводка, человек, сервер. Источники — история использования (объём и время в сети),
/// попытки подключения (AwgAllocations) и проверки с Москвы. Направления: down — к пользователю (Tx сервера),
/// up — от пользователя (Rx сервера). Трафик пути Xray агент пока не считает.
/// </summary>
public static class StatsService
{
    public static readonly TimeSpan OnlineWindow = TimeSpan.FromSeconds(UsageMath.OnlineWindowSeconds);
    /// <summary>Попытка без подтверждения дольше этого считается неудачной, даже если место ещё не освобождено.</summary>
    public static readonly TimeSpan PendingLimit = TimeSpan.FromMinutes(2);

    public enum AttemptState { Connected, Ended, Failed, Pending }

    public static AttemptState StateOf(DateTime createdAt, DateTime? provenAt, DateTime? releasedAt, DateTime now) =>
        provenAt != null ? (releasedAt == null ? AttemptState.Connected : AttemptState.Ended)
        : releasedAt != null || now - createdAt > PendingLimit ? AttemptState.Failed : AttemptState.Pending;

    public static double? Percentile(IEnumerable<double> values, double p)
    {
        var a = values.OrderBy(x => x).ToArray();
        if (a.Length == 0) return null;
        var rank = p * (a.Length - 1);
        int lo = (int)Math.Floor(rank), hi = (int)Math.Ceiling(rank);
        return Math.Round(a[lo] + (a[hi] - a[lo]) * (rank - lo), 1);
    }

    sealed record Attempt(Guid DeviceId, Guid ServerId, DateTime CreatedAt, DateTime? ProvenAt, DateTime? ReleasedAt);

    /// <summary>Итог по попыткам: всего, подтверждено, неудачных, медиана и 90-й перцентиль времени до подключения (с).</summary>
    static object AttemptSummary(IReadOnlyCollection<Attempt> list, DateTime now)
    {
        var settled = list.Where(a => StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now) != AttemptState.Pending).ToList();
        var proven = settled.Where(a => a.ProvenAt != null).ToList();
        var ttc = proven.Select(a => Math.Max(0, (a.ProvenAt!.Value - a.CreatedAt).TotalSeconds)).ToList();
        return new
        {
            total = settled.Count,
            proven = proven.Count,
            failed = settled.Count - proven.Count,
            successPercent = settled.Count == 0 ? (double?)null : Math.Round(100.0 * proven.Count / settled.Count, 1),
            medianSeconds = Percentile(ttc, .5),
            p90Seconds = Percentile(ttc, .9),
        };
    }

    static List<DateTime> Days(DateTime now, int days)
    {
        var last = UsageMath.DayBucket(now);
        return Enumerable.Range(0, days).Select(i => last.AddDays(i - days + 1)).ToList();
    }

    static List<DateTime> Hours(DateTime now, int hours)
    {
        var last = UsageMath.HourBucket(now);
        return Enumerable.Range(0, hours).Select(i => last.AddHours(i - hours + 1)).ToList();
    }

    static async Task<List<Attempt>> AttemptsAsync(MayakDb db, DateTime from, Guid? serverId, IReadOnlyCollection<Guid>? deviceIds, CancellationToken ct)
    {
        var q = db.AwgAllocations.AsNoTracking().Where(a => a.CreatedAt >= from);
        if (serverId is Guid sid) q = q.Where(a => a.ServerId == sid);
        if (deviceIds != null) q = q.Where(a => deviceIds.Contains(a.DeviceId));
        return (await q.Select(a => new { a.DeviceId, a.ServerId, a.CreatedAt, a.ProvenAt, a.ReleasedAt }).ToListAsync(ct))
            .Select(a => new Attempt(a.DeviceId, a.ServerId, a.CreatedAt, a.ProvenAt, a.ReleasedAt)).ToList();
    }

    // ───── Сводка по всем ─────
    public static async Task<object> OverviewAsync(MayakDb db, DateTime now, int days, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 7, 366);
        var dayList = Days(now, days);
        var from = dayList[0];
        var hour24 = UsageMath.HourBucket(now).AddHours(-23);
        var onlineFrom = now - OnlineWindow;

        var accounts = await db.Accounts.AsNoTracking().Select(a => new { a.Id, a.Name, a.Enabled, a.PaidUntil, a.Role }).ToListAsync(ct);
        var devices = await db.Devices.AsNoTracking().Select(d => new { d.Id, d.AccountId, d.Name, d.Kind, d.AppVersion, d.OsVersion, d.LastHandshake, d.Enabled }).ToListAsync(ct);
        var servers = await db.Servers.AsNoTracking().Where(s => s.Role == ServerRoles.Exit).OrderBy(s => s.Name)
            .Select(s => new { s.Id, s.Name, s.City, s.Country, s.Active, s.AutoSelectEnabled, s.LastSeen, s.AgentVersion, s.ProvisioningStatus, s.NativeCapacity }).ToListAsync(ct);
        var serverDaily = await db.ServerUsage.AsNoTracking().Where(u => u.Span == UsageMath.DaySpan && u.Bucket >= from).ToListAsync(ct);
        var serverHourly = await db.ServerUsage.AsNoTracking().Where(u => u.Span == UsageMath.HourSpan && u.Bucket >= hour24).ToListAsync(ct);
        var deviceDaily = await db.DeviceUsage.AsNoTracking().Where(u => u.Span == UsageMath.DaySpan && u.Bucket >= from)
            .Select(u => new { u.DeviceId, u.ServerId, u.Bucket, u.RxBytes, u.TxBytes, u.OnlineSeconds }).ToListAsync(ct);
        var peersNow = await db.PeerCounters.AsNoTracking().Where(c => c.LastHandshake > onlineFrom).GroupBy(c => c.ServerId)
            .Select(g => new { ServerId = g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.ServerId, x => x.Count, ct);
        var attempts = await AttemptsAsync(db, from, null, null, ct);
        var probes = await db.ServerProbes.AsNoTracking().Where(p => p.At > now.AddHours(-24) && p.Error != "unavailable")
            .Select(p => new { p.ServerId, p.Kind, p.At, p.Ok }).ToListAsync(ct);

        var accountOf = devices.ToDictionary(d => d.Id, d => d.AccountId);
        var accountName = accounts.ToDictionary(a => a.Id, a => a.Name);
        var today = dayList[^1];
        var week = now.AddDays(-7);
        bool Active(long rx, long tx, int sec) => sec > 0 || rx + tx > 0;

        var series = dayList.Select(d =>
        {
            var su = serverDaily.Where(u => u.Bucket == d).ToList();
            var du = deviceDaily.Where(u => u.Bucket == d && Active(u.RxBytes, u.TxBytes, u.OnlineSeconds)).ToList();
            var at = attempts.Where(a => UsageMath.DayBucket(a.CreatedAt) == d && StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now) != AttemptState.Pending).ToList();
            return new
            {
                day = UsageMath.DayLabel(d),
                down = su.Sum(u => u.TxBytes), up = su.Sum(u => u.RxBytes),
                devices = du.Select(u => u.DeviceId).Distinct().Count(),
                accounts = du.Select(u => accountOf.GetValueOrDefault(u.DeviceId)).Distinct().Count(),
                peak = su.Count == 0 ? 0 : su.Sum(u => u.PeakPeers),
                attempts = at.Count, proven = at.Count(a => a.ProvenAt != null),
            };
        }).ToList();

        var activeDevicesToday = deviceDaily.Where(u => u.Bucket == today && Active(u.RxBytes, u.TxBytes, u.OnlineSeconds)).Select(u => u.DeviceId).ToHashSet();
        var activeDevices7 = deviceDaily.Where(u => u.Bucket >= today.AddDays(-6) && Active(u.RxBytes, u.TxBytes, u.OnlineSeconds)).Select(u => u.DeviceId).ToHashSet();
        var activeDevicesN = deviceDaily.Where(u => Active(u.RxBytes, u.TxBytes, u.OnlineSeconds)).Select(u => u.DeviceId).ToHashSet();

        var serverRows = servers.Select(s =>
        {
            var h = serverHourly.Where(u => u.ServerId == s.Id).ToList();
            var d = serverDaily.Where(u => u.ServerId == s.Id).ToList();
            var tcp = probes.Where(p => p.ServerId == s.Id && p.Kind == "tcp").ToList();
            var lastTcp = tcp.OrderByDescending(p => p.At).FirstOrDefault();
            return new
            {
                s.Id, s.Name, s.City, s.Country, s.Active, s.AutoSelectEnabled, s.LastSeen, s.AgentVersion, s.ProvisioningStatus, capacity = s.NativeCapacity,
                reporting = s.LastSeen > now.AddMinutes(-3),
                peersNow = peersNow.GetValueOrDefault(s.Id),
                peak24h = h.Count == 0 ? 0 : h.Max(u => u.PeakPeers),
                down24h = h.Sum(u => u.TxBytes), up24h = h.Sum(u => u.RxBytes),
                down = d.Sum(u => u.TxBytes), up = d.Sum(u => u.RxBytes),
                attempts7d = AttemptSummary(attempts.Where(a => a.ServerId == s.Id && a.CreatedAt >= week).ToList(), now),
                tcpUptime24h = tcp.Count == 0 ? (double?)null : Math.Round(100.0 * tcp.Count(p => p.Ok) / tcp.Count, 1),
                tcpLastOk = lastTcp?.Ok,
            };
        }).ToList();

        var topAccounts = deviceDaily.GroupBy(u => accountOf.GetValueOrDefault(u.DeviceId))
            .Select(g => new { accountId = g.Key, name = accountName.GetValueOrDefault(g.Key) ?? "—", down = g.Sum(u => u.TxBytes), up = g.Sum(u => u.RxBytes), onlineSeconds = g.Sum(u => (long)u.OnlineSeconds) })
            .OrderByDescending(x => x.down + x.up).Take(10).ToList();

        var versions = devices.GroupBy(d => new { kind = d.Kind.ToString(), version = d.AppVersion ?? "" })
            .Select(g => new { g.Key.kind, g.Key.version, devices = g.Count(), active = g.Count(d => activeDevicesN.Contains(d.Id)) })
            .OrderBy(x => x.kind).ThenByDescending(x => x.version).ToList();

        // Требует внимания: что стоит посмотреть администратору прямо сейчас.
        var attention = new List<object>();
        foreach (var s in serverRows)
        {
            if ((s.Active || s.AutoSelectEnabled) && !s.reporting)
                attention.Add(new { level = "bad", kind = "server", id = s.Id, text = $"{s.Name}: агент не выходит на связь" });
            if ((s.Active || s.AutoSelectEnabled) && s.tcpLastOk == false)
                attention.Add(new { level = "bad", kind = "server", id = s.Id, text = $"{s.Name}: порт недоступен с Москвы" });
        }
        var day1 = now.AddDays(-1);
        foreach (var g in attempts.Where(a => a.CreatedAt >= day1).GroupBy(a => a.DeviceId))
        {
            var settled = g.Where(a => StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now) != AttemptState.Pending).OrderByDescending(a => a.CreatedAt).ToList();
            if (settled.Count >= 3 && settled.Take(3).All(a => a.ProvenAt == null))
            {
                var dev = devices.FirstOrDefault(d => d.Id == g.Key);
                if (dev != null) attention.Add(new { level = "bad", kind = "account", id = dev.AccountId, text = $"{accountName.GetValueOrDefault(dev.AccountId)} · {dev.Name}: последние {Math.Min(settled.Count, 3)} попытки подключения неудачны" });
            }
        }
        foreach (var a in accounts.Where(a => a.Enabled && a.PaidUntil is DateTime until && until < now.AddDays(7)))
            attention.Add(new { level = a.PaidUntil < now ? "bad" : "warn", kind = "account", id = a.Id, text = a.PaidUntil < now ? $"{a.Name}: срок доступа истёк" : $"{a.Name}: доступ заканчивается {UsageMath.DayLabel(UsageMath.DayBucket(a.PaidUntil!.Value))}" });
        var waiting = accounts.Count(a => !a.Enabled);
        if (waiting > 0) attention.Add(new { level = "warn", kind = "accounts", id = (Guid?)null, text = $"Ждут одобрения: {waiting}" });
        var stale = devices.Count(d => d.Enabled && (d.LastHandshake == null || d.LastHandshake < now.AddDays(-30)));
        if (stale > 0) attention.Add(new { level = "info", kind = "accounts", id = (Guid?)null, text = $"Устройств без подключений 30+ дней: {stale}" });

        var sinceHistory = await db.ServerUsage.AsNoTracking().Where(u => u.Span == UsageMath.DaySpan).MinAsync(u => (DateTime?)u.Bucket, ct);
        return new
        {
            at = now, days,
            historyFrom = sinceHistory is DateTime h0 ? UsageMath.DayLabel(h0) : null,
            totals = new
            {
                accounts = accounts.Count, accountsEnabled = accounts.Count(a => a.Enabled),
                devices = devices.Count,
                onlineNow = devices.Count(d => d.LastHandshake > onlineFrom),
                accountsOnlineNow = devices.Where(d => d.LastHandshake > onlineFrom).Select(d => d.AccountId).Distinct().Count(),
                activeToday = activeDevicesToday.Select(id => accountOf.GetValueOrDefault(id)).Distinct().Count(),
                active7d = activeDevices7.Select(id => accountOf.GetValueOrDefault(id)).Distinct().Count(),
                activeN = activeDevicesN.Select(id => accountOf.GetValueOrDefault(id)).Distinct().Count(),
                downToday = serverDaily.Where(u => u.Bucket == today).Sum(u => u.TxBytes),
                upToday = serverDaily.Where(u => u.Bucket == today).Sum(u => u.RxBytes),
                down = serverDaily.Sum(u => u.TxBytes), up = serverDaily.Sum(u => u.RxBytes),
                peersNow = peersNow.Values.Sum(),
            },
            attempts7d = AttemptSummary(attempts.Where(a => a.CreatedAt >= week).ToList(), now),
            series, servers = serverRows, topAccounts, versions,
            kinds = devices.GroupBy(d => d.Kind.ToString()).Select(g => new { kind = g.Key, devices = g.Count(), active = g.Count(d => activeDevicesN.Contains(d.Id)) }).OrderByDescending(x => x.devices).ToList(),
            attention,
        };
    }

    // ───── Короткая сводка по людям для списка ─────
    public static async Task<object> AccountsSummaryAsync(MayakDb db, DateTime now, CancellationToken ct = default)
    {
        var from30 = UsageMath.DayBucket(now).AddDays(-29);
        var from7 = UsageMath.DayBucket(now).AddDays(-6);
        var devices = await db.Devices.AsNoTracking().Select(d => new { d.Id, d.AccountId, d.LastHandshake }).ToListAsync(ct);
        var usage = await db.DeviceUsage.AsNoTracking().Where(u => u.Span == UsageMath.DaySpan && u.Bucket >= from30)
            .GroupBy(u => new { u.DeviceId, Week = u.Bucket >= from7 })
            .Select(g => new { g.Key.DeviceId, g.Key.Week, Rx = g.Sum(u => u.RxBytes), Tx = g.Sum(u => u.TxBytes), Sec = g.Sum(u => (long)u.OnlineSeconds) }).ToListAsync(ct);
        var day1 = now.AddDays(-1);
        var attempts = await AttemptsAsync(db, day1, null, null, ct);
        var accountOf = devices.ToDictionary(d => d.Id, d => d.AccountId);
        return devices.GroupBy(d => d.AccountId).Select(g =>
        {
            var ids = g.Select(d => d.Id).ToHashSet();
            var u = usage.Where(x => ids.Contains(x.DeviceId)).ToList();
            var at = attempts.Where(a => ids.Contains(a.DeviceId) && StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now) != AttemptState.Pending).ToList();
            return new
            {
                accountId = g.Key,
                down30 = u.Sum(x => x.Tx), up30 = u.Sum(x => x.Rx),
                online7dSeconds = u.Where(x => x.Week).Sum(x => x.Sec),
                lastSeen = g.Max(d => d.LastHandshake),
                online = g.Any(d => d.LastHandshake > now - OnlineWindow),
                attempts24h = at.Count, failed24h = at.Count(a => a.ProvenAt == null),
            };
        }).ToList();
    }

    // ───── Человек ─────
    public static async Task<object?> AccountAsync(MayakDb db, Guid accountId, DateTime now, int days, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 7, 366);
        var account = await db.Accounts.AsNoTracking().Where(a => a.Id == accountId).Select(a => new { a.Id, a.Name }).FirstOrDefaultAsync(ct);
        if (account == null) return null;
        var devices = await db.Devices.AsNoTracking().Where(d => d.AccountId == accountId)
            .Select(d => new { d.Id, d.Name, d.Kind, d.AppVersion, d.OsVersion, d.LastHandshake, d.ConfigFetchedAt, d.CreatedAt, d.Enabled, d.AwgPublicKey }).ToListAsync(ct);
        var ids = devices.Select(d => d.Id).ToList();
        var dayList = Days(now, days);
        var hourList = Hours(now, 48);
        var daily = await db.DeviceUsage.AsNoTracking().Where(u => ids.Contains(u.DeviceId) && u.Span == UsageMath.DaySpan && u.Bucket >= dayList[0]).ToListAsync(ct);
        var hourly = await db.DeviceUsage.AsNoTracking().Where(u => ids.Contains(u.DeviceId) && u.Span == UsageMath.HourSpan && u.Bucket >= hourList[0]).ToListAsync(ct);
        var serverNames = await db.Servers.AsNoTracking().ToDictionaryAsync(s => s.Id, s => s.City.Length > 0 ? s.City : s.Name, ct);
        var keys = devices.Select(d => d.AwgPublicKey).Where(k => k.Length > 0).ToList();
        var counters = await db.PeerCounters.AsNoTracking().Where(c => keys.Contains(c.PublicKey)).Select(c => new { c.ServerId, c.PublicKey, c.LastHandshake }).ToListAsync(ct);
        var attempts = (await AttemptsAsync(db, now.AddDays(-days), null, ids, ct)).OrderByDescending(a => a.CreatedAt).ToList();
        var week = now.AddDays(-7);
        var week7 = dayList[^1].AddDays(-6);

        return new
        {
            account.Id, days,
            series = dayList.Select(d => { var u = daily.Where(x => x.Bucket == d).ToList(); return new { day = UsageMath.DayLabel(d), down = u.Sum(x => x.TxBytes), up = u.Sum(x => x.RxBytes), onlineSeconds = u.Sum(x => (long)x.OnlineSeconds) }; }),
            hourly = hourList.Select(h => { var u = hourly.Where(x => x.Bucket == h).ToList(); return new { at = h, down = u.Sum(x => x.TxBytes), up = u.Sum(x => x.RxBytes), onlineSeconds = u.Sum(x => (long)x.OnlineSeconds) }; }),
            totals = new
            {
                down = daily.Sum(x => x.TxBytes), up = daily.Sum(x => x.RxBytes),
                online7dSeconds = daily.Where(x => x.Bucket >= week7).Sum(x => (long)x.OnlineSeconds),
                activeDays = daily.Where(x => x.OnlineSeconds > 0 || x.RxBytes + x.TxBytes > 0).Select(x => x.Bucket).Distinct().Count(),
            },
            attempts7d = AttemptSummary(attempts.Where(a => a.CreatedAt >= week).ToList(), now),
            devices = devices.Select(d =>
            {
                var u = daily.Where(x => x.DeviceId == d.Id).ToList();
                var c = counters.Where(x => x.PublicKey == d.AwgPublicKey && d.AwgPublicKey.Length > 0).OrderByDescending(x => x.LastHandshake).FirstOrDefault();
                return new
                {
                    d.Id, d.Name, kind = d.Kind.ToString(), d.AppVersion, d.OsVersion, d.LastHandshake, d.ConfigFetchedAt, d.CreatedAt, d.Enabled,
                    online = d.LastHandshake > now - OnlineWindow,
                    server = c == null ? null : serverNames.GetValueOrDefault(c.ServerId),
                    down = u.Sum(x => x.TxBytes), up = u.Sum(x => x.RxBytes),
                    online7dSeconds = u.Where(x => x.Bucket >= week7).Sum(x => (long)x.OnlineSeconds),
                };
            }).OrderByDescending(d => d.LastHandshake).ToList(),
            servers = daily.GroupBy(x => x.ServerId).Select(g => new { serverId = g.Key, name = serverNames.GetValueOrDefault(g.Key) ?? "—", down = g.Sum(x => x.TxBytes), up = g.Sum(x => x.RxBytes), onlineSeconds = g.Sum(x => (long)x.OnlineSeconds) })
                .OrderByDescending(x => x.down + x.up).ToList(),
            recent = attempts.Take(30).Select(a =>
            {
                var state = StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now);
                return new
                {
                    at = a.CreatedAt,
                    device = devices.FirstOrDefault(d => d.Id == a.DeviceId)?.Name ?? "—",
                    server = serverNames.GetValueOrDefault(a.ServerId) ?? "—",
                    state = state.ToString().ToLowerInvariant(),
                    connectSeconds = a.ProvenAt is DateTime p ? Math.Round(Math.Max(0, (p - a.CreatedAt).TotalSeconds), 1) : (double?)null,
                    durationSeconds = a.ProvenAt is DateTime p2 ? (long)Math.Max(0, ((a.ReleasedAt ?? now) - p2).TotalSeconds) : (long?)null,
                };
            }),
        };
    }

    // ───── Сервер ─────
    public static async Task<object?> ServerAsync(MayakDb db, Guid serverId, DateTime now, int days, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 7, 366);
        var server = await db.Servers.AsNoTracking().Where(s => s.Id == serverId).Select(s => new { s.Id, s.Name, s.NativeCapacity }).FirstOrDefaultAsync(ct);
        if (server == null) return null;
        var dayList = Days(now, days);
        var hourList = Hours(now, 48);
        var daily = await db.ServerUsage.AsNoTracking().Where(u => u.ServerId == serverId && u.Span == UsageMath.DaySpan && u.Bucket >= dayList[0]).ToListAsync(ct);
        var hourly = await db.ServerUsage.AsNoTracking().Where(u => u.ServerId == serverId && u.Span == UsageMath.HourSpan && u.Bucket >= hourList[0]).ToListAsync(ct);
        var deviceDaily = await db.DeviceUsage.AsNoTracking().Where(u => u.ServerId == serverId && u.Span == UsageMath.DaySpan && u.Bucket >= dayList[0])
            .Select(u => new { u.DeviceId, u.Bucket, u.RxBytes, u.TxBytes, u.OnlineSeconds }).ToListAsync(ct);
        var devices = await db.Devices.AsNoTracking().Select(d => new { d.Id, d.Name, d.AccountId, d.AwgPublicKey, Account = d.Account!.Name }).ToListAsync(ct);
        var byKey = devices.Where(d => d.AwgPublicKey.Length > 0).GroupBy(d => d.AwgPublicKey).ToDictionary(g => g.Key, g => g.First());
        var onlineFrom = now - OnlineWindow;
        var peers = await db.PeerCounters.AsNoTracking().Where(c => c.ServerId == serverId && c.LastHandshake > onlineFrom)
            .Select(c => new { c.PublicKey, c.LastHandshake }).ToListAsync(ct);
        var attempts = await AttemptsAsync(db, now.AddDays(-days), serverId, null, ct);
        var week = now.AddDays(-7);

        return new
        {
            server.Id, days, capacity = server.NativeCapacity,
            hourly = hourList.Select(h => { var u = hourly.FirstOrDefault(x => x.Bucket == h); return new { at = h, down = u?.TxBytes ?? 0, up = u?.RxBytes ?? 0, peak = u?.PeakPeers ?? 0, avgPeers = u == null ? 0 : Math.Round(u.PeerSeconds / 3600.0, 1) }; }),
            series = dayList.Select(d =>
            {
                var u = daily.FirstOrDefault(x => x.Bucket == d);
                var at = attempts.Where(a => UsageMath.DayBucket(a.CreatedAt) == d && StateOf(a.CreatedAt, a.ProvenAt, a.ReleasedAt, now) != AttemptState.Pending).ToList();
                return new
                {
                    day = UsageMath.DayLabel(d), down = u?.TxBytes ?? 0, up = u?.RxBytes ?? 0, peak = u?.PeakPeers ?? 0,
                    devices = deviceDaily.Where(x => x.Bucket == d && (x.OnlineSeconds > 0 || x.RxBytes + x.TxBytes > 0)).Select(x => x.DeviceId).Distinct().Count(),
                    attempts = at.Count, proven = at.Count(a => a.ProvenAt != null),
                };
            }),
            totals = new { down = daily.Sum(x => x.TxBytes), up = daily.Sum(x => x.RxBytes), peak = daily.Count == 0 ? 0 : daily.Max(x => x.PeakPeers), peerHours = Math.Round(daily.Sum(x => x.PeerSeconds) / 3600.0, 1) },
            attempts7d = AttemptSummary(attempts.Where(a => a.CreatedAt >= week).ToList(), now),
            now = peers.Select(p => byKey.TryGetValue(p.PublicKey, out var d)
                    ? new { account = d.Account, accountId = (Guid?)d.AccountId, device = d.Name, p.LastHandshake }
                    : new { account = "Не из Маяка", accountId = (Guid?)null, device = "", p.LastHandshake })
                .OrderBy(x => x.account).ToList(),
            top = deviceDaily.GroupBy(x => x.DeviceId).Select(g =>
            {
                var d = devices.FirstOrDefault(x => x.Id == g.Key);
                return new { accountId = d?.AccountId, account = d?.Account ?? "—", device = d?.Name ?? "—", down = g.Sum(x => x.TxBytes), up = g.Sum(x => x.RxBytes), onlineSeconds = g.Sum(x => (long)x.OnlineSeconds) };
            }).OrderByDescending(x => x.down + x.up).Take(10).ToList(),
        };
    }
}
