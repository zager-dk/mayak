using Mayak.Core.Models;
using Mayak.Core.Server;

namespace Mayak.Core.Probe;

public enum CheckStatus { Ok, Warn, Fail, Skipped }

public sealed class CheckLine
{
    public string Protocol { get; set; } = "";
    public CheckStatus Status { get; set; }
    public string Summary { get; set; } = "";
    public string Details { get; set; } = "";
}

/// <summary>Отчёт одной проверки — сохраняется в историю.</summary>
public sealed class CheckReport
{
    public DateTime At { get; set; } = DateTime.Now;
    public string ServerHost { get; set; } = "";
    public string ClientAddress { get; set; } = "";
    public string NetworkLabel { get; set; } = "";
    public List<CheckLine> Lines { get; set; } = new();
    public string Recommendation { get; set; } = "";
}

/// <summary>Прогоняет все доступные протоколы с этого компьютера и даёт вердикт.</summary>
public static class ProtocolCheck
{
    public static async Task<CheckReport> RunAsync(ServerSnapshot snap, ProbeIdentity probe, string clientAddress,
        Func<IProgress<string>?, CancellationToken, Task<string>>? ensureXray, IProgress<string>? progress, CancellationToken ct,
        int sshPort = 22, XraySelfTestResult? xraySelfTest = null)
    {
        var report = new CheckReport { ServerHost = snap.Endpoint.Host, ClientAddress = clientAddress };

        // ── Доступен ли сам IP сервера (TCP до SSH-порта)
        progress?.Report("Связь с сервером…");
        var reach = await TcpReachAsync(snap.Endpoint.Host, sshPort, ct);
        report.Lines.Add(new CheckLine
        {
            Protocol = "Связь с сервером",
            Status = reach.Ok ? (reach.Ms < 3 ? CheckStatus.Warn : CheckStatus.Ok) : CheckStatus.Fail,
            Summary = reach.Ok
                ? (reach.Ms < 3 ? "Соединение перехвачено локальным VPN/прокси" : $"IP доступен · {reach.Ms:0} мс")
                : "IP сервера недоступен из этой сети",
            Details = reach.Ok
                ? (reach.Ms < 3
                    ? $"TCP-соединение до {snap.Endpoint.Host} за {reach.Ms:0.#} мс — так быстро бывает, только если его перехватывает программа на этом компьютере (Browsec и т. п.). Результаты ниже могут быть недостоверны."
                    : $"TCP до {snap.Endpoint.Host}:{sshPort} за {reach.Ms:0} мс.")
                : $"TCP до {snap.Endpoint.Host}:{sshPort} не устанавливается ({reach.Error}). Если и протоколы ниже не работают — адрес сервера, вероятно, заблокирован целиком: нужен новый IP или вход через другой сервер.",
        });

        // ── AmneziaWG
        var awg = await AwgProbe.RunAsync(new AwgProbeSettings
        {
            Host = snap.Endpoint.Host,
            Port = snap.Endpoint.Port,
            ServerPublicKey = snap.Endpoint.ServerPublicKey,
            PresharedKey = snap.Endpoint.PresharedKey,
            ClientPrivateKey = probe.AwgPrivateKey,
            ClientIp = probe.AwgIp,
            ServerTunnelIp = snap.ServerAddress,
            Parameters = snap.Endpoint.Parameters,
            DnsServer = string.IsNullOrWhiteSpace(snap.Db.Dns1) ? "1.1.1.1" : snap.Db.Dns1,
        }, progress, ct);
        report.Lines.Add(Describe(awg, snap.Endpoint.Parameters.ProtocolVersionString, snap.Endpoint.Port));

        // ── Xray
        if (snap.Xray == null)
        {
            report.Lines.Add(new CheckLine
            {
                Protocol = "Xray (VLESS + Reality)",
                Status = CheckStatus.Skipped,
                Summary = "Не установлен на сервере",
                Details = "Установите Xray на вкладке «Сервер», чтобы был запасной протокол.",
            });
        }
        else if (ensureXray == null || string.IsNullOrEmpty(probe.XrayId))
        {
            report.Lines.Add(new CheckLine { Protocol = snap.Xray.Title, Status = CheckStatus.Skipped, Summary = "Проверка недоступна" });
        }
        else
        {
            string? exe = null;
            string? exeError = null;
            try { exe = await ensureXray(progress, ct); }
            catch (Exception ex) when (!ct.IsCancellationRequested) { exeError = ex.Message; }

            if (exe == null)
            {
                report.Lines.Add(new CheckLine { Protocol = snap.Xray.Title, Status = CheckStatus.Skipped, Summary = "Нет xray.exe для проверки", Details = exeError ?? "" });
            }
            else
            {
                var x = await XrayProbe.RunAsync(exe, snap.Endpoint.Host, snap.Xray, probe.XrayId, progress, ct);
                report.Lines.Add(Describe(x, snap.Xray, xraySelfTest));
            }
        }

        report.Recommendation = Recommend(report.Lines);
        return report;
    }

    public static CheckLine Describe(AwgProbeResult r, string version, int port)
    {
        var line = new CheckLine { Protocol = $"AmneziaWG {version}" };
        var details = new List<string>();
        if (r.HandshakeOk) details.Add($"Рукопожатие: {r.HandshakeMs:0} мс (попыток: {r.HandshakeAttempts}).");
        if (r.PingSent > 0)
            details.Add($"Пакеты: {r.PingReceived} из {r.PingSent}, потери {r.LossPercent:0.#}%, задержка {r.RttAvgMs:0} мс (макс. {r.RttMaxMs:0}), прошло {r.BytesConfirmed / 1024} КБ.");
        if (r.DnsOk == true) details.Add($"Выход в интернет через сервер: есть (DNS {r.DnsMs:0} мс).");
        if (r.DnsOk == false) details.Add("Выход в интернет через сервер: DNS не ответил.");
        if (r.Error != null) details.Add(r.Error);

        if (!r.HandshakeOk)
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Не подключается";
            details.Insert(0, $"Сервер не ответил на рукопожатие. Либо UDP-порт {port} закрыт файрволом хостинга, либо протокол режется по сигнатуре.");
        }
        else if (r.PingReceived == 0)
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Подключается, но данные не идут";
        }
        else if (r.StalledAfterPing != null)
        {
            line.Status = CheckStatus.Warn;
            line.Summary = $"Данные остановились после ~{r.BytesConfirmed / 1024} КБ";
            details.Insert(0, "Похоже на «заморозку»: фильтр пропустил начало и оборвал поток.");
        }
        else if (r.LossPercent > 10)
        {
            line.Status = CheckStatus.Warn;
            line.Summary = $"Работает с потерями {r.LossPercent:0}%";
        }
        else if (r.DnsOk == false)
        {
            line.Status = CheckStatus.Warn;
            line.Summary = "Туннель работает, но нет выхода в интернет";
        }
        else
        {
            line.Status = CheckStatus.Ok;
            line.Summary = $"Работает · {r.RttAvgMs:0} мс · потери {r.LossPercent:0.#}%";
        }
        line.Details = string.Join(Environment.NewLine, details);
        return line;
    }

    public static CheckLine Describe(XrayProbeResult r, XrayEndpoint ep, XraySelfTestResult? selfTest = null)
    {
        var line = new CheckLine { Protocol = ep.Title };
        var details = new List<string> { $"Маскировка под {ep.Sni}, TCP-порт {ep.Port}." };
        if (selfTest != null) details.Add(selfTest.Details);
        bool intercepted = r.TcpOk && r.TcpMs < 3;
        bool realCert = r.Error?.Contains("received real certificate", StringComparison.OrdinalIgnoreCase) == true;
        if (intercepted)
            details.Add("TCP-соединение установилось мгновенно — его перехватил локальный VPN/прокси, до вашего сервера проверка не дошла.");
        if (realCert)
            details.Add($"Xray получил настоящий сертификат {ep.Sni}: соединение попало не на ваш сервер, а на сам сайт — так бывает, когда VPN/прокси на компьютере перенаправляет трафик по имени сайта, или когда ключи Reality не совпадают.");
        if (r.TcpOk) details.Add($"TCP-соединение: {r.TcpMs:0} мс.");
        if (r.ConnectOk) details.Add($"Соединение через Reality: {r.ConnectMs:0} мс.");
        if (r.DownloadedBytes > 0) details.Add($"Скачано {r.DownloadedBytes / 1024 / 1024.0:0.0} МБ, скорость {r.Mbps:0.#} Мбит/с.");
        if (r.Error != null) details.Add(r.Error);

        if (!r.TcpOk)
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Порт недоступен";
        }
        else if (selfTest is { Ok: false })
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Ошибка настройки Xray на сервере";
        }
        else if (!r.ConnectOk && intercepted)
        {
            line.Status = CheckStatus.Skipped;
            line.Summary = "Не проверено: мешает локальный VPN";
        }
        else if (!r.ConnectOk)
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Не подключается";
        }
        else if (r.StalledAfterBytes != null)
        {
            line.Status = CheckStatus.Warn;
            line.Summary = $"Поток остановился после {r.StalledAfterBytes / 1024} КБ";
            details.Insert(0, "Похоже на «заморозку» по поведению: соединение есть, но данные перестают идти.");
        }
        else if (r.DownloadedBytes == 0)
        {
            line.Status = CheckStatus.Warn;
            line.Summary = "Подключается, скорость не измерена";
        }
        else
        {
            line.Status = CheckStatus.Ok;
            line.Summary = $"Работает · {r.Mbps:0} Мбит/с";
        }
        line.Details = string.Join(Environment.NewLine, details);
        return line;
    }

    private static async Task<(bool Ok, double Ms, string Error)> TcpReachAsync(string host, int port, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(7));
            await tcp.ConnectAsync(host, port, cts.Token);
            return (true, sw.Elapsed.TotalMilliseconds, "");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, 0, "нет ответа 7 с");
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            return (false, 0, ex.Message);
        }
    }

    private static string Recommend(List<CheckLine> lines)
    {
        lines = lines.Where(l => l.Protocol != "Связь с сервером").ToList();
        var working = lines.Where(l => l.Status == CheckStatus.Ok).Select(l => l.Protocol).ToList();
        var partly = lines.Where(l => l.Status == CheckStatus.Warn).Select(l => l.Protocol).ToList();
        if (working.Count == lines.Count(l => l.Status != CheckStatus.Skipped) && working.Count > 0)
            return "Из этой сети работают все проверенные протоколы.";
        if (working.Count > 0)
            return $"Из этой сети стабильно работает: {string.Join(", ", working)}. Посоветуйте пользователям в такой сети переключиться на него в AmneziaVPN.";
        if (partly.Count > 0)
            return $"Частично работает: {string.Join(", ", partly)}. Стоит сменить порт или сайт маскировки Reality и проверить снова.";
        return "Из этой сети ничего не проходит. Проверьте, не включён ли на компьютере другой VPN; при «белых списках» на мобильной сети нужен вход через российский сервер.";
    }
}
