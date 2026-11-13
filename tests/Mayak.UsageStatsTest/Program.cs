using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Agent;
using Mayak.Core.Xray;
using Microsoft.EntityFrameworkCore;
using Npgsql;

// История использования и статистика админки.
// Часть 1 — арифметика без БД. Часть 2 — одноразовая база на локальном PostgreSQL (127.0.0.1:55432), удаляется в конце.
// dotnet run --project tests/Mayak.UsageStatsTest -- "Host=127.0.0.1;Port=55432;Username=postgres"
var failed = 0; var passed = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}"); if (ok) passed++; else failed++; }
DateTime U(int y, int mo, int d, int h, int mi = 0, int s = 0) => new(y, mo, d, h, mi, s, DateTimeKind.Utc);

// ───── 1. Арифметика ─────
Check("час: начало часа UTC", UsageMath.HourBucket(U(2026, 11, 12, 21, 37, 5)) == U(2026, 11, 12, 21));
Check("сутки по Москве: 21:30 UTC — уже следующий день", UsageMath.DayBucket(U(2026, 11, 12, 21, 30)) == U(2026, 11, 12, 21) && UsageMath.DayLabel(U(2026, 11, 12, 21)) == "2026-11-13");
Check("сутки по Москве: 20:59 UTC — ещё тот же день", UsageMath.DayBucket(U(2026, 11, 12, 20, 59)) == U(2026, 11, 11, 21) && UsageMath.DayLabel(U(2026, 11, 11, 21)) == "2026-11-12");
Check("первый отчёт о пире — только база", UsageMath.Delta(null, null, 5_000_000, 9_000_000) == (0, 0));
Check("обычный прирост", UsageMath.Delta(100, 200, 150, 260) == (50, 60));
Check("счётчик сброшен перезапуском — прирост равен новому значению", UsageMath.Delta(1000, 2000, 30, 40) == (30, 40));
var now0 = U(2026, 11, 13, 10);
Check("в сети: рукопожатие 2 мин назад", UsageMath.IsOnline(now0.AddMinutes(-2), now0));
Check("не в сети: рукопожатие 4 мин назад или нет", !UsageMath.IsOnline(now0.AddMinutes(-4), now0) && !UsageMath.IsOnline(null, now0));
Check("время в сети: промежуток между отчётами", UsageMath.OnlineSeconds(now0.AddSeconds(-30), now0, true) == 30);
Check("время в сети: длинный промежуток обрезан до 180 с", UsageMath.OnlineSeconds(now0.AddMinutes(-20), now0, true) == 180);
Check("время в сети: не в сети или первый отчёт — 0", UsageMath.OnlineSeconds(now0.AddSeconds(-30), now0, false) == 0 && UsageMath.OnlineSeconds(null, now0, true) == 0);
Check("попытка: подтверждена и идёт", StatsService.StateOf(now0, now0.AddSeconds(3), null, now0) == StatsService.AttemptState.Connected);
Check("попытка: подтверждена и завершена", StatsService.StateOf(now0, now0.AddSeconds(3), now0.AddHours(1), now0.AddHours(2)) == StatsService.AttemptState.Ended);
Check("попытка: освобождена без подтверждения — неудачна", StatsService.StateOf(now0, null, now0.AddSeconds(20), now0.AddMinutes(1)) == StatsService.AttemptState.Failed);
Check("попытка: без подтверждения дольше 2 мин — неудачна", StatsService.StateOf(now0, null, null, now0.AddMinutes(3)) == StatsService.AttemptState.Failed);
Check("попытка: идёт меньше 2 мин — ещё не итог", StatsService.StateOf(now0, null, null, now0.AddMinutes(1)) == StatsService.AttemptState.Pending);
Check("медиана и 90-й перцентиль", StatsService.Percentile([1, 2, 3, 4, 100], .5) == 3 && StatsService.Percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], .9) == 9.1 && StatsService.Percentile([], .5) == null);

// ───── 1б. Нагрузка сервера и счётчики Xray (без БД) ─────
const string serverJson = """{"log":{"loglevel":"error"},"inbounds":[{"port":443,"protocol":"vless","settings":{"clients":[{"id":"x","email":"mayak:1"}],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"reality"}}],"outbounds":[{"protocol":"freedom"}]}""";
Check("Xray: без счётчиков — не включены", !XrayConfig.HasUserStats(serverJson));
var withStats = XrayConfig.EnableUserStats(serverJson);
Check("Xray: после включения — включены, клиенты и inbound на месте",
    XrayConfig.HasUserStats(withStats) && XrayConfig.ReadClients(withStats).Single().Email == "mayak:1" &&
    JsonDocument.Parse(withStats).RootElement.GetProperty("inbounds").GetArrayLength() == 1);
Check("Xray: включение повторно ничего не ломает", XrayConfig.HasUserStats(XrayConfig.EnableUserStats(withStats)));
Check("Xray: API слушает только 127.0.0.1", JsonDocument.Parse(withStats).RootElement.GetProperty("api").GetProperty("listen").GetString() == "127.0.0.1:10085");
Check("Xray: замена клиентов сохраняет счётчики", XrayConfig.HasUserStats(XrayConfig.ReplaceClients(withStats, [new XrayConfig.Client("y", "mayak:2", "")])));
var statsOut = """
{
    "stat": [
        { "name": "user>>>mayak:aa>>>traffic>>>downlink" },
        { "name": "user>>>mayak:aa>>>traffic>>>uplink", "value": 79 },
        { "name": "user>>>mayak:bb>>>traffic>>>downlink", "value": "123456789012" },
        { "name": "inbound>>>api>>>traffic>>>uplink", "value": 5 }
    ]
}
""";
var parsed = XrayConfig.ParseUserStats(statsOut);
Check("Xray: разбор statsquery — ноль опущен, число строкой, чужие счётчики пропущены",
    parsed.Count == 2 && parsed[0] == new XrayConfig.UserTraffic("mayak:aa", 79, 0) && parsed[1] == new XrayConfig.UserTraffic("mayak:bb", 0, 123456789012));
Check("Xray: пустой и битый вывод — пусто", XrayConfig.ParseUserStats("{}").Count == 0 && XrayConfig.ParseUserStats("failed to dial").Count == 0);
var devGuid = Guid.NewGuid();
Check("Xray: email → устройство", UsageRecorder.DeviceFromXrayEmail("mayak:" + devGuid.ToString("N")) == devGuid &&
    UsageRecorder.DeviceFromXrayEmail("mayak:probe") == null && UsageRecorder.DeviceFromXrayEmail(devGuid.ToString("N")) == null);

string HostOut(long user, long idle, long rx, long tx) => $"""
@@STAT
cpu  {user} 0 0 {idle} 0 0 0 0 0 0
@@LOAD
0.42 0.30 0.20 3/250 1234
@@MEM
MemTotal:        2015212 kB
MemAvailable:    1338148 kB
@@UPTIME
1209600.55 1000.00
@@NPROC
1
@@DEV
eth0
@@NET
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0
  eth0: {rx} 100 0 0 0 0 0 0 {tx} 100 0 0 0 0 0 0
  awg0: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0
@@DF
50884108288 46819471360
""";
var (h1, c1) = HostStatsReader.Parse(HostOut(1000, 9000, 1_000_000, 2_000_000), null);
Check("нагрузка: первый замер — без процента процессора, остальное есть",
    h1.CpuPercent == null && c1 == new HostStatsReader.CpuTimes(9000, 10000) && h1.Cpus == 1 && h1.Load1 == 0.42 &&
    h1.MemTotalBytes == 2015212L * 1024 && h1.MemAvailableBytes == 1338148L * 1024 && h1.UptimeSeconds == 1209600 &&
    h1.NetInterface == "eth0" && h1.NetRxBytes == 1_000_000 && h1.NetTxBytes == 2_000_000 && h1.DiskTotalBytes == 50884108288 && h1.DiskFreeBytes == 46819471360);
var (h2, _) = HostStatsReader.Parse(HostOut(1300, 9700, 1_500_000, 2_900_000), c1);
Check("нагрузка: процессор по разнице двух замеров", h2.CpuPercent == 30);
var (h3, _) = HostStatsReader.Parse(HostOut(1300, 9700, 1, 1).Replace("@@DEV\neth0\n", "@@DEV\n"), null);
Check("нагрузка: без маршрута по умолчанию — самый нагруженный физический интерфейс", h3.NetInterface == "eth0");
var (h4, c4) = HostStatsReader.Parse("garbage", null);
Check("нагрузка: мусор не роняет разбор", c4 == null && h4.MemTotalBytes == 0 && h4.NetInterface == "");
var lr = JsonSerializer.Serialize(new AgentReport { At = DateTime.UtcNow, Host = h2, XrayStatsEnabled = true });
var latest = JsonDocument.Parse(JsonSerializer.Serialize(StatsService.LatestHost(lr, DateTime.UtcNow))).RootElement;
Check("нагрузка: последняя из LastReport — доли и свежесть",
    latest.GetProperty("cpu").GetDouble() == 30 && latest.GetProperty("memPercent").GetDouble() == 33.6 && latest.GetProperty("fresh").GetBoolean() && latest.GetProperty("xrayStats").GetBoolean());
Check("нагрузка: старый отчёт без Host — нет данных", StatsService.LatestHost(JsonSerializer.Serialize(new AgentReport()), DateTime.UtcNow) == null && StatsService.LatestHost("{bad", DateTime.UtcNow) == null);

// ───── 2. База ─────
var server = args.ElementAtOrDefault(0) ?? "Host=127.0.0.1;Port=55432;Username=postgres";
var csb = new NpgsqlConnectionStringBuilder(server);
if (csb.Host != "127.0.0.1" || csb.Port != 55432) { Console.WriteLine("Нужен одноразовый локальный PostgreSQL 127.0.0.1:55432"); return 2; }
var dbName = "mayak_usagetest_" + Guid.NewGuid().ToString("N")[..8];
var options = new DbContextOptionsBuilder<MayakDb>().UseNpgsql($"{server};Database={dbName}").Options;
try
{
    await using (var db = new MayakDb(options)) await db.Database.MigrateAsync();
    var accId = Guid.NewGuid(); var devA = Guid.NewGuid(); var devB = Guid.NewGuid(); var oslo = Guid.NewGuid(); var vienna = Guid.NewGuid();
    string Key(char c) => new string(c, 43) + "=";
    await using (var db = new MayakDb(options))
    {
        db.Accounts.Add(new Account { Id = accId, Name = "Мама" });
        db.Devices.Add(new Device { Id = devA, AccountId = accId, Name = "Телефон", Kind = Mayak.Core.Models.DeviceKind.Android, AwgPublicKey = Key('A'), Ip = "10.8.1.2", AppVersion = "5.1.0.21" });
        db.Devices.Add(new Device { Id = devB, AccountId = accId, Name = "Ноутбук", Kind = Mayak.Core.Models.DeviceKind.Windows, AwgPublicKey = Key('B'), Ip = "10.8.1.3", AppVersion = "5.1.0.22" });
        db.Servers.Add(new Server { Id = oslo, Name = "Осло", City = "Осло", Role = ServerRoles.Exit, Host = "192.0.2.1", AgentTokenHash = "t1", Active = true, LastSeen = DateTime.UtcNow });
        db.Servers.Add(new Server { Id = vienna, Name = "Вена", City = "Вена", Role = ServerRoles.Exit, Host = "192.0.2.2", AgentTokenHash = "t2" });
        await db.SaveChangesAsync();
    }
    // Отчёты: 20:59 и 20:59:30 UTC (12.11, 23:59 по МСК) и 21:00:30 UTC — уже 13.11 по Москве.
    var t0 = U(2026, 11, 12, 20, 59, 0);
    async Task Report(Guid srv, DateTime at, params AgentPeerStats[] peers)
    {
        await using var db = new MayakDb(options);
        await using var tx = await db.Database.BeginTransactionAsync();
        await UsageRecorder.RecordAsync(db, srv, peers, at);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
    }
    AgentPeerStats P(char k, long rx, long tx, DateTime? hs) => new() { PublicKey = Key(k), RxBytes = rx, TxBytes = tx, LatestHandshake = hs };

    await Report(oslo, t0, P('A', 1_000, 10_000, t0.AddSeconds(-20)), P('Z', 500, 500, t0));                     // база
    await Report(oslo, t0.AddSeconds(30), P('A', 1_500, 16_000, t0.AddSeconds(10)), P('Z', 800, 900, t0));          // +500/+6000, 30 с в сети
    await Report(oslo, t0.AddSeconds(90), P('A', 100, 2_000, t0.AddSeconds(80)), P('Z', 900, 1_000, t0.AddMinutes(-10))); // сброс; 60 с; Z не в сети
    await Report(vienna, t0.AddSeconds(90), P('B', 0, 0, null));

    await using (var db = new MayakDb(options))
    {
        var du = await db.DeviceUsage.AsNoTracking().ToListAsync();
        var su = await db.ServerUsage.AsNoTracking().ToListAsync();
        var dayOld = U(2026, 11, 11, 21); var dayNew = U(2026, 11, 12, 21);
        var aDayOld = du.Single(x => x.DeviceId == devA && x.Span == 24 && x.Bucket == dayOld);
        var aDayNew = du.Single(x => x.DeviceId == devA && x.Span == 24 && x.Bucket == dayNew);
        Check("устройство: прирост до полуночи МСК — в старых сутках", aDayOld.RxBytes == 500 && aDayOld.TxBytes == 6_000 && aDayOld.OnlineSeconds == 30);
        Check("устройство: после сброса счётчика — новые сутки, прирост = новое значение", aDayNew.RxBytes == 100 && aDayNew.TxBytes == 2_000 && aDayNew.OnlineSeconds == 60);
        Check("устройство: часовые записи тоже есть", du.Count(x => x.DeviceId == devA && x.Span == 1) == 2);
        Check("неопознанный пир не пишется в устройства", du.All(x => x.DeviceId == devA));
        Check("устройство без трафика и не в сети — без записей", !du.Any(x => x.DeviceId == devB));
        var oOld = su.Single(x => x.ServerId == oslo && x.Span == 24 && x.Bucket == dayOld);
        var oNew = su.Single(x => x.ServerId == oslo && x.Span == 24 && x.Bucket == dayNew);
        Check("сервер: в итог входит и неопознанный пир", oOld.RxBytes == 500 + 300 && oOld.TxBytes == 6_000 + 400 && oOld.Reports == 2);
        Check("сервер: пик подключённых и сумма времени", oOld.PeakPeers == 2 && oOld.PeerSeconds == 60 && oNew.PeakPeers == 1 && oNew.PeerSeconds == 60);
        Check("сервер без пиров тоже отмечает отчёт", su.Any(x => x.ServerId == vienna && x.Span == 1 && x.Reports == 1 && x.PeakPeers == 0));
        var counters = await db.PeerCounters.AsNoTracking().Where(c => c.ServerId == oslo).ToListAsync();
        Check("счётчики хранят последнее значение и рукопожатие", counters.Count == 2 && counters.Single(c => c.PublicKey == Key('A')).RxBytes == 100 && counters.Single(c => c.PublicKey == Key('A')).LastHandshake == t0.AddSeconds(80));
    }

    // Попытки подключения и сводки.
    var now = t0.AddMinutes(2);
    await using (var db = new MayakDb(options))
    {
        db.AwgAllocations.Add(new AwgAllocation { DeviceId = devA, ServerId = oslo, AttemptId = "a1", CreatedAt = now.AddHours(-3), ProvenAt = now.AddHours(-3).AddSeconds(4), ReleasedAt = now.AddHours(-1) });
        db.AwgAllocations.Add(new AwgAllocation { DeviceId = devA, ServerId = oslo, AttemptId = "a2", CreatedAt = now.AddMinutes(-30), ProvenAt = now.AddMinutes(-30).AddSeconds(6) });
        for (var i = 0; i < 3; i++)
            db.AwgAllocations.Add(new AwgAllocation { DeviceId = devB, ServerId = vienna, AttemptId = "b" + i, CreatedAt = now.AddMinutes(-20 + i), ReleasedAt = now.AddMinutes(-19 + i) });
        db.AwgAllocations.Add(new AwgAllocation { DeviceId = devB, ServerId = vienna, AttemptId = "b9", CreatedAt = now.AddSeconds(-30) }); // ещё идёт
        await db.SaveChangesAsync();
    }
    await using (var db = new MayakDb(options))
    {
        var j = (object o) => JsonDocument.Parse(JsonSerializer.Serialize(o)).RootElement;
        var ov = j(await StatsService.OverviewAsync(db, now, 30));
        var series = ov.GetProperty("series").EnumerateArray().ToList();
        Check("сводка: 30 суток, последние — 13.11", series.Count == 30 && series[^1].GetProperty("day").GetString() == "2026-11-13");
        Check("сводка: down = Tx сервера, up = Rx", series[^2].GetProperty("down").GetInt64() == 6_400 && series[^2].GetProperty("up").GetInt64() == 800);
        Check("сводка: активные люди и устройства за сутки", series[^2].GetProperty("accounts").GetInt32() == 1 && series[^2].GetProperty("devices").GetInt32() == 1);
        var at7 = ov.GetProperty("attempts7d");
        Check("сводка: попытки за 7 дней без незавершённой", at7.GetProperty("total").GetInt32() == 5 && at7.GetProperty("proven").GetInt32() == 2 && at7.GetProperty("successPercent").GetDouble() == 40);
        Check("сводка: медиана времени до подключения", at7.GetProperty("medianSeconds").GetDouble() == 5);
        var attention = ov.GetProperty("attention").EnumerateArray().Select(a => a.GetProperty("text").GetString()!).ToList();
        Check("внимание: устройство с тремя неудачами подряд", attention.Any(t => t.Contains("Ноутбук") && t.Contains("неудачны")));
        var osloRow = ov.GetProperty("servers").EnumerateArray().Single(s => s.GetProperty("Name").GetString() == "Осло");
        Check("сводка: сервер — пик за 24 ч и трафик", osloRow.GetProperty("peak24h").GetInt32() == 2 && osloRow.GetProperty("down").GetInt64() == 6_400 + 2_000 + 100);

        var acc = j((await StatsService.AccountAsync(db, accId, now, 30))!);
        Check("человек: итог трафика по всем устройствам", acc.GetProperty("totals").GetProperty("down").GetInt64() == 8_000 && acc.GetProperty("totals").GetProperty("up").GetInt64() == 600);
        Check("человек: 48 часовых точек", acc.GetProperty("hourly").GetArrayLength() == 48);
        var phone = acc.GetProperty("devices").EnumerateArray().Single(d => d.GetProperty("Name").GetString() == "Телефон");
        Check("человек: устройство знает последний сервер", phone.GetProperty("server").GetString() == "Осло" && phone.GetProperty("online7dSeconds").GetInt64() == 90);
        var recent = acc.GetProperty("recent").EnumerateArray().ToList();
        Check("человек: последние попытки с состоянием", recent.Count == 6 && recent[0].GetProperty("state").GetString() == "pending" && recent.Any(r => r.GetProperty("state").GetString() == "connected" && r.GetProperty("connectSeconds").GetDouble() == 6));
        Check("человек: неизвестный — 404", await StatsService.AccountAsync(db, Guid.NewGuid(), now, 30) == null);

        var srv = j((await StatsService.ServerAsync(db, oslo, now, 30))!);
        Check("сервер: топ устройств с именем человека", srv.GetProperty("top")[0].GetProperty("account").GetString() == "Мама" && srv.GetProperty("top")[0].GetProperty("device").GetString() == "Телефон");
        Check("сервер: 48 часовых точек и итог", srv.GetProperty("hourly").GetArrayLength() == 48 && srv.GetProperty("totals").GetProperty("peak").GetInt32() == 2);
        Check("сервер: подключены сейчас — только свежие рукопожатия", srv.GetProperty("now").GetArrayLength() == 1 && srv.GetProperty("now")[0].GetProperty("account").GetString() == "Мама");

        var sum = j(await StatsService.AccountsSummaryAsync(db, now));
        var row = sum.EnumerateArray().Single();
        Check("список людей: трафик 30 дней и неудачи за сутки", row.GetProperty("down30").GetInt64() == 8_000 && row.GetProperty("failed24h").GetInt32() == 3);
    }

    // Xray и нагрузка: отдельный сервер, Ноутбук ходит через Xray.
    var hel = Guid.NewGuid();
    await using (var db = new MayakDb(options))
    {
        db.Servers.Add(new Server { Id = hel, Name = "Хельсинки", City = "Хельсинки", Role = ServerRoles.Exit, Host = "192.0.2.3", AgentTokenHash = "t3", LastSeen = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }
    async Task ReportFull(DateTime at, AgentReport r)
    {
        await using var db = new MayakDb(options);
        await using var tx = await db.Database.BeginTransactionAsync();
        await UsageRecorder.RecordAsync(db, hel, r, at);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
    }
    AgentXrayUserStats XU(Guid dev, long up, long down) => new() { Email = "mayak:" + dev.ToString("N"), UplinkBytes = up, DownlinkBytes = down };
    AgentHostStats HS(double? cpu, long avail, long rx, long tx) => new() { CpuPercent = cpu, Cpus = 1, Load1 = 0.5, MemTotalBytes = 2_000_000_000, MemAvailableBytes = avail, DiskTotalBytes = 50_000_000_000, DiskFreeBytes = 40_000_000_000, NetInterface = "eth0", NetRxBytes = rx, NetTxBytes = tx, UptimeSeconds = 100 };
    var t1 = now; // 21:01 UTC, всё в одном часе
    await ReportFull(t1, new AgentReport { XrayStatsEnabled = true, XrayUsers = [XU(devB, 1_000, 5_000), new() { Email = "mayak:probe", UplinkBytes = 9, DownlinkBytes = 9 }, XU(Guid.NewGuid(), 7, 7)], Host = HS(null, 1_500_000_000, 1_000_000, 2_000_000) });
    await ReportFull(t1.AddSeconds(30), new AgentReport { XrayStatsEnabled = true, XrayUsers = [XU(devB, 3_000, 25_000)], Host = HS(25, 1_000_000_000, 1_500_000, 2_900_000) });
    await ReportFull(t1.AddSeconds(60), new AgentReport { XrayStatsEnabled = true, XrayUsers = [XU(devB, 3_000, 25_000)], Host = HS(75, 1_200_000_000, 1_600_000, 3_000_000) });
    await ReportFull(t1.AddSeconds(90), new AgentReport { XrayStatsEnabled = false, XrayUsers = [XU(devB, 9_000_000, 9_000_000)] }); // старый агент: ни Xray, ни нагрузки
    await using (var db = new MayakDb(options))
    {
        var hour = UsageMath.HourBucket(t1);
        var d = await db.DeviceUsage.AsNoTracking().SingleAsync(x => x.DeviceId == devB && x.ServerId == hel && x.Span == 1 && x.Bucket == hour);
        Check("Xray: устройство — прирост после базы, отдельно доля Xray, 30 с в сети", d.RxBytes == 2_000 && d.TxBytes == 20_000 && d.XrayRxBytes == 2_000 && d.XrayTxBytes == 20_000 && d.OnlineSeconds == 30);
        var u = await db.ServerUsage.AsNoTracking().SingleAsync(x => x.ServerId == hel && x.Span == 1 && x.Bucket == hour);
        Check("Xray: сервер — трафик, пик, неизвестные и служебные клиенты не учтены", u.RxBytes == 2_000 && u.TxBytes == 20_000 && u.XrayRxBytes == 2_000 && u.XrayTxBytes == 20_000 && u.PeakPeers == 1 && u.Reports == 4);
        Check("нагрузка: процессор — 2 замера, среднее 50, пик 75", u.CpuSamples == 2 && u.CpuSum == 100 && u.CpuMax == 75);
        Check("нагрузка: память — максимум занятой, диск и сеть по разнице", u.MemUsedMax == 1_000_000_000 && u.MemTotal == 2_000_000_000 && u.DiskTotal == 50_000_000_000 && u.DiskFree == 40_000_000_000 && u.NetRxBytes == 600_000 && u.NetTxBytes == 1_000_000 && u.Load1Max == 0.5);
        var keys = await db.PeerCounters.AsNoTracking().Where(c => c.ServerId == hel).Select(c => c.PublicKey).OrderBy(k => k).ToListAsync();
        Check("счётчики: Xray по устройству и сеть сервера, без служебных", keys.SequenceEqual(new[] { "host:net:eth0", UsageRecorder.XrayKey(devB) }.OrderBy(k => k)));
    }
    await using (var db = new MayakDb(options))
    {
        var j = (object o) => JsonDocument.Parse(JsonSerializer.Serialize(o)).RootElement;
        var n2 = t1.AddSeconds(100);
        var srv = j((await StatsService.ServerAsync(db, hel, n2, 30))!);
        var nowList = srv.GetProperty("now").EnumerateArray().ToList();
        Check("сервер: подключён сейчас через Xray", nowList.Count == 1 && nowList[0].GetProperty("device").GetString() == "Ноутбук" && nowList[0].GetProperty("protocol").GetString() == "Xray");
        var hr = srv.GetProperty("hourly").EnumerateArray().Last();
        Check("сервер: час — процессор, память, сеть, Xray", hr.GetProperty("cpu").GetDouble() == 50 && hr.GetProperty("cpuMax").GetDouble() == 75 && hr.GetProperty("memUsed").GetInt64() == 1_000_000_000 && hr.GetProperty("netIn").GetInt64() == 600_000 && hr.GetProperty("xrayDown").GetInt64() == 20_000);
        Check("сервер: итог — Xray и средний процессор", srv.GetProperty("totals").GetProperty("xrayDown").GetInt64() == 20_000 && srv.GetProperty("totals").GetProperty("cpu").GetDouble() == 50);
        var acc = j((await StatsService.AccountAsync(db, accId, n2, 30))!);
        var laptop = acc.GetProperty("devices").EnumerateArray().Single(x => x.GetProperty("Name").GetString() == "Ноутбук");
        Check("человек: устройство в сети через Xray на Хельсинки", laptop.GetProperty("online").GetBoolean() && laptop.GetProperty("protocol").GetString() == "Xray" && laptop.GetProperty("server").GetString() == "Хельсинки" && laptop.GetProperty("xrayDown").GetInt64() == 20_000);
        var ov = j(await StatsService.OverviewAsync(db, n2, 30));
        Check("сводка: в сети через Xray и трафик Xray", ov.GetProperty("totals").GetProperty("onlineXrayNow").GetInt32() == 1 && ov.GetProperty("totals").GetProperty("xrayDown").GetInt64() == 20_000);
        var helRow = ov.GetProperty("servers").EnumerateArray().Single(s => s.GetProperty("Name").GetString() == "Хельсинки");
        Check("сводка: процессор сервера за 24 ч", helRow.GetProperty("cpu24hAvg").GetDouble() == 50 && helRow.GetProperty("cpu24hMax").GetDouble() == 75);
        var later = j(await StatsService.OverviewAsync(db, t1.AddMinutes(10), 30));
        Check("сводка: без трафика 3+ мин Xray-устройство уже не в сети", later.GetProperty("totals").GetProperty("onlineXrayNow").GetInt32() == 0);
    }

    // Сроки хранения и каскадное удаление.
    await using (var db = new MayakDb(options))
    {
        var old = UsageMath.HourBucket(now).AddDays(-20);
        db.DeviceUsage.Add(new DeviceUsage { DeviceId = devA, ServerId = oslo, Span = 1, Bucket = old, RxBytes = 1 });
        db.DeviceUsage.Add(new DeviceUsage { DeviceId = devA, ServerId = oslo, Span = 24, Bucket = UsageMath.DayBucket(old), RxBytes = 1 });
        db.DeviceUsage.Add(new DeviceUsage { DeviceId = devA, ServerId = oslo, Span = 24, Bucket = UsageMath.DayBucket(now).AddDays(-400), RxBytes = 1 });
        db.ServerUsage.Add(new ServerUsage { ServerId = oslo, Span = 1, Bucket = old });
        db.PeerCounters.Add(new PeerCounter { ServerId = vienna, PublicKey = Key('Q'), At = now.AddDays(-3) });
        await db.SaveChangesAsync();
        var removed = await UsageRecorder.PruneAsync(db, now, 14, 366);
        Check("очистка: часы старше 14 дней, сутки старше года, старые счётчики", removed == 4);
        Check("очистка: сутки 20-дневной давности остаются", await db.DeviceUsage.AnyAsync(u => u.Span == 24 && u.Bucket == UsageMath.DayBucket(old)));
    }
    await using (var db = new MayakDb(options))
    {
        // Как в API: новый контекст на запрос; историю удаляет каскад в базе.
        db.Devices.Remove(await db.Devices.SingleAsync(d => d.Id == devA));
        await db.SaveChangesAsync();
        Check("удаление устройства удаляет его историю", !await db.DeviceUsage.AnyAsync(u => u.DeviceId == devA));
    }
}
finally
{
    NpgsqlConnection.ClearAllPools();
    await using var conn = new NpgsqlConnection($"{server};Database=postgres");
    await conn.OpenAsync();
    await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{dbName}\" WITH (FORCE)", conn);
    await cmd.ExecuteNonQueryAsync();
}

Console.WriteLine($"passed={passed} failed={failed}");
return failed == 0 ? 0 : 1;
