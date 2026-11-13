using System.Globalization;

namespace Mayak.Core.Agent;

/// <summary>
/// Нагрузка сервера из /proc и df одной командой. Читаются только числа: доли процессора, память, диск,
/// счётчики байтов сетевого интерфейса. Ни процессов, ни адресов, ни содержимого (правило 5).
/// </summary>
public static class HostStatsReader
{
    /// <summary>Время процессора из первой строки /proc/stat: простой (idle+iowait) и всего.</summary>
    public sealed record CpuTimes(long Idle, long Total);

    public const string Command =
        "echo @@STAT; head -1 /proc/stat 2>/dev/null; " +
        "echo @@LOAD; cat /proc/loadavg 2>/dev/null; " +
        "echo @@MEM; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo 2>/dev/null; " +
        "echo @@UPTIME; cat /proc/uptime 2>/dev/null; " +
        "echo @@NPROC; nproc 2>/dev/null; " +
        "echo @@DEV; ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<NF;i++) if($i==\"dev\"){print $(i+1); exit}}'; " +
        "echo @@NET; cat /proc/net/dev 2>/dev/null; " +
        "echo @@DF; df -B1 --output=size,avail / 2>/dev/null | tail -1";

    public static (AgentHostStats Stats, CpuTimes? Cpu) Parse(string output, CpuTimes? previous)
    {
        var sections = new Dictionary<string, List<string>>();
        List<string>? cur = null;
        foreach (var raw in output.Replace("\r", "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("@@", StringComparison.Ordinal)) { cur = new List<string>(); sections[line[2..]] = cur; continue; }
            if (line.Length > 0) cur?.Add(line);
        }
        List<string> S(string name) => sections.TryGetValue(name, out var l) ? l : new List<string>();

        var stats = new AgentHostStats();
        CpuTimes? cpu = null;
        var stat = S("STAT").FirstOrDefault(l => l.StartsWith("cpu ", StringComparison.Ordinal));
        if (stat != null)
        {
            var f = stat.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(L).ToArray();
            if (f.Length >= 4)
            {
                // user nice system idle iowait irq softirq steal (guest уже входит в user).
                long total = f.Take(8).Sum();
                long idle = f[3] + (f.Length > 4 ? f[4] : 0);
                cpu = new CpuTimes(idle, total);
                if (previous != null && total > previous.Total && idle >= previous.Idle)
                {
                    var dTotal = total - previous.Total;
                    var dIdle = Math.Min(idle - previous.Idle, dTotal);
                    stats.CpuPercent = Math.Round(100.0 * (dTotal - dIdle) / dTotal, 1);
                }
            }
        }

        var load = S("LOAD").FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (load is { Length: > 0 }) stats.Load1 = D(load[0]);

        foreach (var l in S("MEM"))
        {
            var p = l.Split(new[] { ' ', ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 2) continue;
            var bytes = L(p[1]) * (p.Length > 2 && p[2].Equals("kB", StringComparison.OrdinalIgnoreCase) ? 1024 : 1);
            if (p[0] == "MemTotal") stats.MemTotalBytes = bytes;
            else if (p[0] == "MemAvailable") stats.MemAvailableBytes = bytes;
        }

        var up = S("UPTIME").FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (up is { Length: > 0 }) stats.UptimeSeconds = (long)D(up[0]);

        stats.Cpus = (int)Math.Clamp(L(S("NPROC").FirstOrDefault() ?? "0"), 0, 4096);

        var dev = S("DEV").FirstOrDefault() ?? "";
        var interfaces = new List<(string Name, long Rx, long Tx)>();
        foreach (var l in S("NET"))
        {
            var colon = l.IndexOf(':');
            if (colon <= 0) continue;
            var name = l[..colon].Trim();
            var f = l[(colon + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 9 || !long.TryParse(f[0], out _)) continue;
            interfaces.Add((name, L(f[0]), L(f[8])));
        }
        // Нет маршрута по умолчанию — берём самый нагруженный физический интерфейс (не lo, не docker, не VPN).
        var pick = interfaces.FirstOrDefault(i => i.Name == dev);
        if (pick.Name == null)
            pick = interfaces.Where(i => i.Name != "lo" && !i.Name.StartsWith("docker") && !i.Name.StartsWith("br-") && !i.Name.StartsWith("veth") && !i.Name.StartsWith("awg") && !i.Name.StartsWith("wg"))
                .OrderByDescending(i => i.Rx + i.Tx).FirstOrDefault();
        if (pick.Name != null)
        {
            stats.NetInterface = pick.Name.Length > 32 ? pick.Name[..32] : pick.Name;
            stats.NetRxBytes = pick.Rx;
            stats.NetTxBytes = pick.Tx;
        }

        var df = S("DF").FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (df is { Length: >= 2 }) { stats.DiskTotalBytes = L(df[0]); stats.DiskFreeBytes = L(df[1]); }
        return (stats, cpu);
    }

    static long L(string s) => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? Math.Max(0, v) : 0;
    static double D(string s) => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) && double.IsFinite(v) ? Math.Max(0, v) : 0;
}
