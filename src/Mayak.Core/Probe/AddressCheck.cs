using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Mayak.Core.Probe;

/// <summary>Чем закончилась попытка TCP-соединения.</summary>
public enum TcpOutcome
{
    /// <summary>Соединение установлено.</summary>
    Open,
    /// <summary>Сервер ответил отказом (порт закрыт) — маршрут до адреса есть.</summary>
    Refused,
    /// <summary>Нет ответа — типичная картина блокировки или отсутствия маршрута.</summary>
    Timeout,
    /// <summary>Сеть недоступна, адрес не определился и т. п.</summary>
    Error,
}

public sealed record TcpProbe(string Host, int Port, TcpOutcome Outcome, double Ms, string Error = "")
{
    /// <summary>До адреса есть маршрут: ответил сервер, а не тишина.</summary>
    public bool Routed => Outcome is TcpOutcome.Open or TcpOutcome.Refused;

    /// <summary>Соединение «установилось» быстрее, чем может пройти пакет за пределы компьютера: его перехватил локальный VPN/прокси.</summary>
    public bool Intercepted => Outcome == TcpOutcome.Open && Ms < 3 && !IsLocalNetwork(Host);

    private static bool IsLocalNetwork(string host)
    {
        if (!IPAddress.TryParse(host, out var ip)) return host == "localhost";
        if (IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        return b.Length == 4 && (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168));
    }

    public string Describe() => Outcome switch
    {
        TcpOutcome.Open => $"{Host}:{Port} — открыт, {Ms:0} мс",
        TcpOutcome.Refused => $"{Host}:{Port} — порт закрыт, но сервер ответил ({Ms:0} мс)",
        TcpOutcome.Timeout => $"{Host}:{Port} — нет ответа",
        _ => $"{Host}:{Port} — ошибка: {Error}",
    };
}

/// <summary>Результаты с одной точки (этот компьютер или входной сервер).</summary>
public sealed class VantageResult
{
    public string Name { get; init; } = "";
    public bool IsLocal { get; init; }
    public List<TcpProbe> Target { get; init; } = new();
    /// <summary>Контроль: заведомо доступный зарубежный адрес.</summary>
    public TcpProbe? ForeignControl { get; init; }
    /// <summary>Контроль: российский адрес (есть ли интернет вообще).</summary>
    public TcpProbe? LocalControl { get; init; }
    /// <summary>Не удалось выполнить проверку (например, нет SSH до входа).</summary>
    public string? Failure { get; init; }

    public bool Routed => Failure == null && Target.Any(t => t.Routed) && !Intercepted;
    public bool Intercepted => Target.Any(t => t.Intercepted);
}

public sealed class AddressCheckReport
{
    public string Host { get; set; } = "";
    public List<CheckLine> Lines { get; } = new();
    public CheckStatus Verdict { get; set; }
    public string VerdictTitle { get; set; } = "";
    public string VerdictText { get; set; } = "";
}

/// <summary>
/// Проверка адреса сервера до установки VPN: доходит ли до него трафик с этого компьютера
/// и с входных серверов. Нужна, потому что из России перестали маршрутизироваться целые
/// диапазоны зарубежных хостингов — такой сервер бесполезен, как его ни настраивай.
/// </summary>
public static class AddressCheck
{
    public static readonly int[] DefaultPorts = { 22, 443 };
    public const string ForeignControlHost = "github.com";
    public const string LocalControlHost = "ya.ru";
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private static readonly Regex HostRe = new(@"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$", RegexOptions.Compiled);

    /// <summary>IP или домен без схемы, порта и пробелов (значение уходит в shell на входном сервере).</summary>
    public static bool IsValidHost(string host) => HostRe.IsMatch(host) && !host.Contains("..");

    /// <summary>Убирает типичный мусор: пробелы, «ssh root@», «:22», «https://».</summary>
    public static string Normalize(string input)
    {
        var s = input.Trim();
        s = Regex.Replace(s, @"^[a-z]+://", "", RegexOptions.IgnoreCase);
        if (s.Contains('@')) s = s[(s.LastIndexOf('@') + 1)..];
        s = s.Split('/', ' ')[0];
        var colon = s.LastIndexOf(':');
        if (colon > 0 && s.IndexOf(':') == colon && int.TryParse(s[(colon + 1)..], out _)) s = s[..colon];
        return s;
    }

    public static async Task<TcpProbe> TcpAsync(string host, int port, CancellationToken ct, TimeSpan? timeout = null)
    {
        var limit = timeout ?? Timeout;
        IPAddress? ip;
        if (!IPAddress.TryParse(host, out ip))
        {
            try
            {
                using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dnsCts.CancelAfter(limit);
                var addrs = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, dnsCts.Token);
                ip = addrs.FirstOrDefault();
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
            {
                ip = null;
            }
            if (ip == null) return new TcpProbe(host, port, TcpOutcome.Error, 0, "не удалось определить IP по имени");
        }

        var sw = Stopwatch.StartNew();
        try
        {
            using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(limit);
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token);
            return new TcpProbe(host, port, TcpOutcome.Open, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TcpProbe(host, port, TcpOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return new TcpProbe(host, port, TcpOutcome.Refused, sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            return new TcpProbe(host, port, TcpOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException ex)
        {
            return new TcpProbe(host, port, TcpOutcome.Error, sw.Elapsed.TotalMilliseconds, ex.Message);
        }
    }

    /// <summary>Проверка с этого компьютера: целевые порты и два контрольных адреса, параллельно.</summary>
    public static async Task<VantageResult> FromThisComputerAsync(string host, IReadOnlyList<int> ports, CancellationToken ct)
    {
        var target = ports.Select(p => TcpAsync(host, p, ct)).ToList();
        var foreign = TcpAsync(ForeignControlHost, 443, ct);
        var local = TcpAsync(LocalControlHost, 443, ct);
        await Task.WhenAll(target.Append(foreign).Append(local));
        return new VantageResult
        {
            Name = "Этот компьютер",
            IsLocal = true,
            Target = target.Select(t => t.Result).ToList(),
            ForeignControl = foreign.Result,
            LocalControl = local.Result,
        };
    }

    /// <summary>Скрипт для входного сервера: строки «MAYAK_TCP host port outcome ms».</summary>
    public static string RemoteScript(string host, IReadOnlyList<int> ports)
    {
        if (!IsValidHost(host)) throw new ArgumentException("Недопустимый адрес", nameof(host));
        var targets = string.Join(" ", ports.Select(p => $"{host}:{p}").Append($"{ForeignControlHost}:443").Append($"{LocalControlHost}:443"));
        var secs = (int)Timeout.TotalSeconds;
        return $$"""
            for t in {{targets}}; do (
              h=${t%:*}; p=${t##*:}
              s=$(date +%s%N)
              err=$(timeout {{secs}} bash -c "</dev/tcp/$h/$p" 2>&1 >/dev/null); rc=$?
              e=$(date +%s%N)
              if [ $rc -eq 0 ]; then r=open
              elif [ $rc -eq 124 ]; then r=timeout
              elif echo "$err" | grep -qi refused; then r=refused
              else r=error; fi
              echo "MAYAK_TCP $h $p $r $(( (e - s) / 1000000 ))"
            ) & done
            wait
            """;
    }

    /// <summary>Разбирает вывод RemoteScript.</summary>
    public static VantageResult ParseRemote(string name, string host, string output)
    {
        var probes = new List<TcpProbe>();
        foreach (var line in output.Split('\n'))
        {
            var p = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 5 || p[0] != "MAYAK_TCP" || !int.TryParse(p[2], out var port)) continue;
            double.TryParse(p[4], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var ms);
            var outcome = p[3] switch
            {
                "open" => TcpOutcome.Open,
                "refused" => TcpOutcome.Refused,
                "timeout" => TcpOutcome.Timeout,
                _ => TcpOutcome.Error,
            };
            probes.Add(new TcpProbe(p[1], port, outcome, ms, outcome == TcpOutcome.Error ? "нет маршрута" : ""));
        }
        if (probes.Count == 0) return new VantageResult { Name = name, Failure = "вход не вернул результат проверки" };
        return new VantageResult
        {
            Name = name,
            Target = probes.Where(x => x.Host == host).ToList(),
            ForeignControl = probes.FirstOrDefault(x => x.Host == ForeignControlHost),
            LocalControl = probes.FirstOrDefault(x => x.Host == LocalControlHost),
        };
    }

    /// <summary>Сводит результаты в строки отчёта и вердикт.</summary>
    public static AddressCheckReport Build(string host, VantageResult local, IReadOnlyList<VantageResult> relays)
    {
        var r = new AddressCheckReport { Host = host };
        r.Lines.Add(Line(local));
        foreach (var v in relays) r.Lines.Add(Line(v));

        var usableRelays = relays.Where(v => v.Routed).Select(v => v.Name).ToList();
        bool localForeignOk = local.ForeignControl?.Routed == true;
        bool localAnyOk = localForeignOk || local.LocalControl?.Routed == true;

        if (local.Intercepted)
        {
            r.Verdict = CheckStatus.Warn;
            r.VerdictTitle = "Выключите VPN на компьютере";
            r.VerdictText = "Соединение перехватывает программа на этом компьютере (Browsec и т. п.), поэтому проверка с него ничего не говорит. Выключите её и проверьте ещё раз." +
                            (usableRelays.Count > 0 ? $" С входа ({string.Join(", ", usableRelays)}) адрес доступен." : "");
        }
        else if (local.Routed)
        {
            r.Verdict = CheckStatus.Ok;
            r.VerdictTitle = "Подходит: сервер доступен напрямую";
            r.VerdictText = "Из вашей сети до адреса есть маршрут. Можно устанавливать VPN, а затем запустить «Проверку» — она покажет, какой протокол проходит (UDP AmneziaWG до установки проверить нельзя)." +
                            (relays.Count > 0 && usableRelays.Count == 0 ? "\nВход его не видит — каскад с этим сервером работать не будет." : "");
        }
        else if (usableRelays.Count > 0)
        {
            r.Verdict = CheckStatus.Warn;
            r.VerdictTitle = "Подходит только через вход";
            r.VerdictText = $"Напрямую адрес недоступен, но его видит {string.Join(", ", usableRelays.Select(n => "«" + n + "»"))}. " +
                            "Подключите этот сервер в Маяке через посредника, установите VPN и настройте вход — пользователи будут подключаться через него.";
        }
        else if (!localAnyOk)
        {
            r.Verdict = CheckStatus.Warn;
            r.VerdictTitle = "Нет интернета на компьютере";
            r.VerdictText = "С этого компьютера не открываются даже контрольные адреса. Проверьте подключение к сети и повторите.";
        }
        else
        {
            r.Verdict = CheckStatus.Fail;
            r.VerdictTitle = "Не подходит: адрес недоступен из России";
            r.VerdictText = (localForeignOk
                                ? $"Зарубежный интернет работает ({ForeignControlHost} открывается), а этот адрес молчит — его диапазон не маршрутизируется из российских сетей. "
                                : $"Из вашей сети не открывается и {ForeignControlHost} — похоже на «белые списки». ") +
                            (relays.Count > 0 ? "Вход его тоже не видит. " : "") +
                            "Смените локацию или хостинг и проверьте новый адрес. Смена IP в той же локации помогает редко.";
        }
        return r;
    }

    private static CheckLine Line(VantageResult v)
    {
        var name = v.IsLocal ? "С этого компьютера" : $"С входа «{v.Name}»";
        if (v.Failure != null)
            return new CheckLine { Protocol = name, Status = CheckStatus.Skipped, Summary = "не проверено", Details = v.Failure };

        var details = string.Join("\n", v.Target.Select(t => t.Describe()));
        var controls = new[] { v.ForeignControl, v.LocalControl }.Where(c => c != null).Select(c => "контроль " + c!.Describe());
        details += "\n" + string.Join("\n", controls);

        if (v.Intercepted)
            return new CheckLine { Protocol = name, Status = CheckStatus.Warn, Summary = "перехвачено локальным VPN", Details = details };
        if (v.Routed)
        {
            var best = v.Target.Where(t => t.Routed).MinBy(t => t.Ms)!;
            return new CheckLine { Protocol = name, Status = CheckStatus.Ok, Summary = $"доступен · {best.Ms:0} мс", Details = details };
        }
        return new CheckLine
        {
            Protocol = name,
            Status = CheckStatus.Fail,
            Summary = v.ForeignControl?.Routed == true ? "недоступен (остальной зарубежный интернет работает)" : "недоступен",
            Details = details,
        };
    }
}
