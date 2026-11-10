using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Mayak.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

/// <summary>
/// Этап A проверки доступности: с машины API (Москва) напрямую до каждого сервера —
/// ICMP, TCP-порт Xray и TLS-рукопожатие с SNI маскировки (Reality отвечает чужим клиентам как настоящий сайт).
/// Это проверка «сервер жив и путь из российского ДЦ открыт», а не проверка DPI мобильных провайдеров:
/// рукопожатие .NET не совпадает с uTLS-отпечатком клиентов. Туннели AWG/Xray — этап B (PROBES_PLAN.md).
/// Пишет только итог и задержку; трафика и адресов пользователей не касается.
/// Фоном раз в 5 минут и по кнопке в админке (<see cref="RunOnceAsync"/>); фон выключается Probes:Background=false.
/// </summary>
public sealed class ServerProbeService(IServiceScopeFactory scopes, IConfiguration cfg, ILogger<ServerProbeService> log) : BackgroundService
{
    public const string Icmp = "icmp", Tcp = "tcp", Tls = "tls";
    private DateTime _lastCleanup = DateTime.MinValue;
    private bool _warned;
    private static readonly SemaphoreSlim RunGate = new(1, 1);

    /// <summary>Один проход проверок (все серверы или один), сохраняет результаты. null — проход уже идёт.</summary>
    public static async Task<List<ServerProbe>?> RunOnceAsync(MayakDb db, Guid? serverId, CancellationToken ct)
    {
        if (!await RunGate.WaitAsync(0, ct)) return null;
        try
        {
            var servers = await db.Servers.AsNoTracking().Where(s => serverId == null || s.Id == serverId)
                .Select(s => new { s.Id, s.Host }).ToListAsync(ct);
            var cluster = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
            var xray = cluster == null ? null : ClusterService.XrayOf(cluster);
            var tasks = servers.Where(s => !string.IsNullOrWhiteSpace(s.Host))
                .Select(s => ProbeServerAsync(s.Id, s.Host.Trim(), xray?.Port, xray?.Sni, ct)).ToList();
            var results = (await Task.WhenAll(tasks)).SelectMany(x => x).ToList();
            db.ServerProbes.AddRange(results);
            await db.SaveChangesAsync(ct);
            var before = DateTime.UtcNow.AddDays(-7);
            await db.ServerProbes.Where(p => p.At < before).ExecuteDeleteAsync(ct);
            return results;
        }
        finally { RunGate.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(cfg.GetValue("Probes:IntervalSeconds", 300), 15, 3600));
        var retention = TimeSpan.FromDays(Math.Clamp(cfg.GetValue("Probes:RetentionDays", 7), 1, 90));
        try { await Task.Delay(TimeSpan.FromSeconds(10), stop); } catch (OperationCanceledException) { return; }
        while (!stop.IsCancellationRequested)
        {
            try { await CycleAsync(retention, stop); _warned = false; }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                if (!_warned) log.LogWarning("Проверка доступности серверов: {Error}", ex.GetType().Name);
                _warned = true;
            }
            try { await Task.Delay(interval, stop); } catch (OperationCanceledException) { return; }
        }
    }

    private async Task CycleAsync(TimeSpan retention, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        await RunOnceAsync(db, null, ct);
        if (DateTime.UtcNow - _lastCleanup > TimeSpan.FromHours(1))
        {
            var before = DateTime.UtcNow - retention;
            await db.ServerProbes.Where(p => p.At < before).ExecuteDeleteAsync(ct);
            _lastCleanup = DateTime.UtcNow;
        }
    }

    private static async Task<List<ServerProbe>> ProbeServerAsync(Guid serverId, string host, int? port, string? sni, CancellationToken ct)
    {
        var at = DateTime.UtcNow;
        var list = new List<ServerProbe>();
        IPAddress? address = null;
        string? resolveError = null;
        try { address = await ResolveAsync(host, ct); }
        catch (Exception) { resolveError = "dns"; }
        list.Add(address == null ? Fail(serverId, at, Icmp, resolveError ?? "dns") : await IcmpAsync(serverId, at, address));
        if (port is int p && p is > 0 and <= 65535)
        {
            list.Add(address == null ? Fail(serverId, at, Tcp, "dns") : await TcpAsync(serverId, at, address, p, ct));
            if (!string.IsNullOrWhiteSpace(sni))
                list.Add(address == null ? Fail(serverId, at, Tls, "dns") : await TlsAsync(serverId, at, address, p, sni!, ct));
        }
        return list;
    }

    private static async Task<IPAddress?> ResolveAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return ip;
        var all = await Dns.GetHostAddressesAsync(host, ct);
        return all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault();
    }

    private static ServerProbe Fail(Guid id, DateTime at, string kind, string error) =>
        new() { ServerId = id, At = at, Kind = kind, Ok = false, Error = error };

    private static async Task<ServerProbe> IcmpAsync(Guid id, DateTime at, IPAddress address)
    {
        var times = new List<long>();
        string? error = null;
        try
        {
            using var ping = new Ping();
            for (var i = 0; i < 3; i++)
            {
                var reply = await ping.SendPingAsync(address, 1500);
                if (reply.Status == IPStatus.Success) times.Add(reply.RoundtripTime);
                else error ??= reply.Status == IPStatus.TimedOut ? "timeout" : "unreachable";
            }
        }
        catch (Exception ex) when (ex is PingException or PlatformNotSupportedException or UnauthorizedAccessException)
        {
            return Fail(id, at, Icmp, "unavailable");
        }
        return times.Count > 0
            ? new ServerProbe { ServerId = id, At = at, Kind = Icmp, Ok = true, LatencyMs = (int)Math.Round(times.Average()), Error = times.Count < 3 ? "loss" : null }
            : Fail(id, at, Icmp, error ?? "timeout");
    }

    private static async Task<ServerProbe> TcpAsync(Guid id, DateTime at, IPAddress address, int port, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            await client.ConnectAsync(address, port, timeout.Token);
            return new ServerProbe { ServerId = id, At = at, Kind = Tcp, Ok = true, LatencyMs = (int)sw.ElapsedMilliseconds };
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return Fail(id, at, Tcp, ErrorCode(ex));
        }
    }

    private static async Task<ServerProbe> TlsAsync(Guid id, DateTime at, IPAddress address, int port, string sni, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(6));
        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            await client.ConnectAsync(address, port, timeout.Token);
            await using var tls = new SslStream(client.GetStream(), false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                // Проверяем только, что рукопожатие проходит до конца; доверие сертификату здесь не нужно.
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }, timeout.Token);
            return new ServerProbe { ServerId = id, At = at, Kind = Tls, Ok = true, LatencyMs = (int)sw.ElapsedMilliseconds };
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return Fail(id, at, Tls, ex is AuthenticationException ? "tls" : ErrorCode(ex));
        }
    }

    public static string ErrorCode(Exception ex) => ex switch
    {
        OperationCanceledException => "timeout",
        SocketException { SocketErrorCode: SocketError.ConnectionRefused } => "refused",
        SocketException { SocketErrorCode: SocketError.ConnectionReset } => "reset",
        SocketException { SocketErrorCode: SocketError.TimedOut } => "timeout",
        SocketException { SocketErrorCode: SocketError.HostUnreachable or SocketError.NetworkUnreachable } => "unreachable",
        IOException { InnerException: SocketException inner } => ErrorCode(inner),
        IOException => "reset",
        AuthenticationException => "tls",
        _ => "error",
    };
}

/// <summary>Сводка проверок для админки: последний результат, доля успешных и задержка по видам, корзины для полосы истории.</summary>
public static class ServerProbeStats
{
    public sealed record Bucket(double? OkRatio, int? AvgMs);
    public sealed record KindSummary(string Kind, bool? LastOk, int? LastMs, string? LastError, DateTime? LastAt,
        double? UptimePercent, int? AvgMs, int Count, IReadOnlyList<Bucket> Buckets);

    public static IReadOnlyList<KindSummary> Summarize(IEnumerable<ServerProbe> probes, DateTime now, TimeSpan window, int buckets)
    {
        var from = now - window;
        var size = window.Ticks / Math.Max(1, buckets);
        var result = new List<KindSummary>();
        foreach (var group in probes.Where(p => p.At > from && p.At <= now).GroupBy(p => p.Kind).OrderBy(g => KindOrder(g.Key)))
        {
            var items = group.OrderBy(p => p.At).ToList();
            // «unavailable» — ICMP запрещён на машине API: это не недоступность сервера, в процент не входит.
            var counted = items.Where(p => p.Error != "unavailable").ToList();
            var last = items[^1];
            var okMs = counted.Where(p => p.Ok && p.LatencyMs != null).Select(p => p.LatencyMs!.Value).ToList();
            var series = new Bucket[buckets];
            for (var i = 0; i < buckets; i++)
            {
                var start = from.Ticks + size * i;
                var inBucket = counted.Where(p => p.At.Ticks > start && p.At.Ticks <= start + size).ToList();
                var ms = inBucket.Where(p => p.Ok && p.LatencyMs != null).Select(p => p.LatencyMs!.Value).ToList();
                series[i] = new Bucket(inBucket.Count == 0 ? null : Math.Round((double)inBucket.Count(p => p.Ok) / inBucket.Count, 3),
                    ms.Count == 0 ? null : (int)Math.Round(ms.Average()));
            }
            result.Add(new KindSummary(group.Key, last.Ok, last.LatencyMs, last.Error, last.At,
                counted.Count == 0 ? null : Math.Round(100.0 * counted.Count(p => p.Ok) / counted.Count, 1),
                okMs.Count == 0 ? null : (int)Math.Round(okMs.Average()), items.Count, series));
        }
        return result;
    }

    private static int KindOrder(string kind) => kind switch { "icmp" => 0, "tcp" => 1, "tls" => 2, "awg" => 3, "xray" => 4, _ => 9 };
}
