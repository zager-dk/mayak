using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Mayak.Core.Models;
using Mayak.Core.Xray;

namespace Mayak.Core.Probe;

public sealed class XrayProbeResult
{
    public bool TcpOk { get; set; }
    public double TcpMs { get; set; }
    public bool ConnectOk { get; set; }
    public double ConnectMs { get; set; }
    public long DownloadedBytes { get; set; }
    public double Mbps { get; set; }
    /// <summary>Скачивание остановилось и больше не шло (признак «заморозки») — сколько байт успело прийти.</summary>
    public long? StalledAfterBytes { get; set; }
    public string? Error { get; set; }
}

/// <summary>Официальный Xray-core: скачивание с GitHub и проверка SHA-256.</summary>
public static class XrayBinary
{
    private static bool IsWindows => OperatingSystem.IsWindows();

    public static string ExeName => IsWindows ? "xray.exe" : "xray";

    public static string Folder(string baseFolder) => Path.Combine(baseFolder, "xray-" + XrayDefaults.Release);

    public static string DownloadUrl => IsWindows
        ? $"https://github.com/XTLS/Xray-core/releases/download/{XrayDefaults.Release}/Xray-windows-64.zip"
        : $"https://github.com/XTLS/Xray-core/releases/download/{XrayDefaults.Release}/Xray-linux-64.zip";

    private static string ExpectedSha256 => IsWindows ? XrayDefaults.WindowsZipSha256 : XrayDefaults.LinuxZipSha256;

    /// <summary>Путь к xray: уже скачанный, положенный вручную или скачанный сейчас.</summary>
    public static async Task<string> EnsureAsync(string baseFolder, IProgress<string>? progress, CancellationToken ct)
    {
        var folder = Folder(baseFolder);
        var exe = Path.Combine(folder, ExeName);
        if (File.Exists(exe)) return exe;

        Directory.CreateDirectory(folder);
        progress?.Report($"Скачиваю Xray {XrayDefaults.Release} с GitHub (около 30 МБ, один раз)…");
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        byte[] zip;
        try
        {
            zip = await http.GetByteArrayAsync(DownloadUrl, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new IOException(
                $"Не удалось скачать Xray: {ex.Message}\nСкачайте вручную {DownloadUrl}, распакуйте {ExeName} в папку:\n{folder}", ex);
        }

        var hash = Convert.ToHexString(SHA256.HashData(zip)).ToLowerInvariant();
        if (hash != ExpectedSha256)
            throw new IOException($"Контрольная сумма Xray не совпала ({hash}). Файл повреждён или подменён — не используем.");

        using (var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
        {
            var entry = archive.GetEntry(ExeName) ?? throw new IOException($"В архиве нет {ExeName}");
            var tmp = exe + ".tmp";
            entry.ExtractToFile(tmp, overwrite: true);
            File.Move(tmp, exe, overwrite: true);
        }
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return exe;
    }
}

/// <summary>Проверка Xray: запускает локальный xray как SOCKS-прокси и ходит через него в интернет.</summary>
public static class XrayProbe
{
    public static async Task<XrayProbeResult> RunAsync(string xrayExe, string host, XrayEndpoint ep, string clientId,
        IProgress<string>? progress = null, CancellationToken ct = default,
        int downloadBytes = 30_000_000, TimeSpan? downloadLimit = null)
    {
        var result = new XrayProbeResult();

        progress?.Report($"Xray: TCP-порт {ep.Port}…");
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(7));
            await tcp.ConnectAsync(host, ep.Port, cts.Token);
            result.TcpOk = true;
            result.TcpMs = sw.Elapsed.TotalMilliseconds;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            result.Error = $"TCP-порт {ep.Port} недоступен: {ex.Message}";
            return result;
        }

        int socksPort = FreePort();
        var configPath = Path.Combine(Path.GetTempPath(), $"mayak-xray-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(configPath, XrayConfig.BuildClientJson(host, ep, clientId, socksPort), ct);

        var psi = new ProcessStartInfo(xrayExe, $"run -c \"{configPath}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(xrayExe)!,
        };
        var log = new System.Text.StringBuilder();
        using var proc = new Process { StartInfo = psi };
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) lock (log) log.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (log) log.AppendLine(e.Data); };

        try
        {
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            // ждём, пока xray откроет SOCKS-порт
            var up = false;
            for (int i = 0; i < 50 && !proc.HasExited; i++)
            {
                await Task.Delay(100, ct);
                try
                {
                    using var t = new TcpClient();
                    await t.ConnectAsync(IPAddress.Loopback, socksPort, ct);
                    up = true;
                    break;
                }
                catch (SocketException) { }
            }
            if (!up)
            {
                result.Error = "Xray не запустился локально:\n" + Tail(log);
                return result;
            }

            var handler = new SocketsHttpHandler
            {
                Proxy = new WebProxy($"socks5://127.0.0.1:{socksPort}"),
                UseProxy = true,
                ConnectTimeout = TimeSpan.FromSeconds(15),
            };
            using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

            progress?.Report("Xray: соединение через Reality…");
            sw.Restart();
            foreach (var url in new[] { "https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204" })
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeSpan.FromSeconds(15));
                    using var resp = await http.GetAsync(url, cts.Token);
                    if ((int)resp.StatusCode is 204 or 200)
                    {
                        result.ConnectOk = true;
                        result.ConnectMs = sw.Elapsed.TotalMilliseconds;
                        break;
                    }
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    result.Error = ex.InnerException?.Message ?? ex.Message;
                }
            }
            if (!result.ConnectOk)
            {
                result.Error = "Соединение через Xray не устанавливается: " + (result.Error ?? "нет ответа") + Environment.NewLine + Tail(log);
                return result;
            }
            result.Error = null;

            progress?.Report("Xray: скачивание для проверки скорости…");
            await DownloadAsync(http, downloadBytes, downloadLimit ?? TimeSpan.FromSeconds(20), result, progress, ct);
        }
        finally
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            try { File.Delete(configPath); } catch { /* ignore */ }
        }
        return result;
    }

    private static async Task DownloadAsync(HttpClient http, int bytes, TimeSpan limit, XrayProbeResult result,
        IProgress<string>? progress, CancellationToken ct)
    {
        var url = $"https://speed.cloudflare.com/__down?bytes={bytes}";
        var sw = Stopwatch.StartNew();
        long total = 0;
        var lastData = sw.Elapsed;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(limit + TimeSpan.FromSeconds(5));
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            resp.EnsureSuccessStatusCode();
            await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token);
            var buf = new byte[64 * 1024];
            while (sw.Elapsed < limit)
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                readCts.CancelAfter(TimeSpan.FromSeconds(8));
                int n;
                try
                {
                    n = await stream.ReadAsync(buf, readCts.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    result.StalledAfterBytes = total;
                    break;
                }
                if (n == 0) break;
                total += n;
                lastData = sw.Elapsed;
                if (total % (5 * 1024 * 1024) < n)
                    progress?.Report($"Xray: скачано {total / 1024 / 1024} МБ…");
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            if (total == 0) result.Error = "Скачивание через Xray не удалось: " + (ex.InnerException?.Message ?? ex.Message);
            else result.StalledAfterBytes ??= total;
        }
        result.DownloadedBytes = total;
        var seconds = Math.Max(0.5, lastData.TotalSeconds);
        result.Mbps = total * 8 / seconds / 1_000_000;
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static string Tail(System.Text.StringBuilder log)
    {
        lock (log)
        {
            var lines = log.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            return string.Join("\n", lines.Skip(Math.Max(0, lines.Length - 8)));
        }
    }
}
