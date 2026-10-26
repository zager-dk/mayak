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
        Func<IProgress<string>?, CancellationToken, Task<string>>? ensureXray, IProgress<string>? progress, CancellationToken ct)
    {
        var report = new CheckReport { ServerHost = snap.Endpoint.Host, ClientAddress = clientAddress };

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
                report.Lines.Add(Describe(x, snap.Xray));
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

    public static CheckLine Describe(XrayProbeResult r, XrayEndpoint ep)
    {
        var line = new CheckLine { Protocol = ep.Title };
        var details = new List<string> { $"Маскировка под {ep.Sni}, TCP-порт {ep.Port}." };
        if (r.TcpOk) details.Add($"TCP-соединение: {r.TcpMs:0} мс.");
        if (r.ConnectOk) details.Add($"Соединение через Reality: {r.ConnectMs:0} мс.");
        if (r.DownloadedBytes > 0) details.Add($"Скачано {r.DownloadedBytes / 1024 / 1024.0:0.0} МБ, скорость {r.Mbps:0.#} Мбит/с.");
        if (r.Error != null) details.Add(r.Error);

        if (!r.TcpOk)
        {
            line.Status = CheckStatus.Fail;
            line.Summary = "Порт недоступен";
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

    private static string Recommend(List<CheckLine> lines)
    {
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
