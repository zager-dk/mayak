using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mayak.Core.Agent;
using Mayak.Core.Models;
using Mayak.Core.Server;

namespace Mayak.Agent;

public sealed class AgentConfig
{
    /// <summary>Адрес API, например https://mayaklight.ru</summary>
    public string Api { get; set; } = "";
    public string Token { get; set; } = "";
    /// <summary>Разрешить отзыв больше половины подключений за раз (по умолчанию нет — защита от сбоя API).</summary>
    public bool AllowMassRemoval { get; set; }
    /// <summary>Адрес этого сервера для клиентов по умолчанию (если не задан — из hostname -I).</summary>
    public string? PublicHost { get; set; }
}

/// <summary>
/// Агент Маяка: знакомится с API, приходит за желаемым состоянием и применяет его на этом сервере
/// через то же ядро, что и Маяк для Windows. Входящих подключений не принимает.
/// </summary>
public sealed class AgentRunner
{
    public static readonly string Version = typeof(AgentRunner).Assembly.GetName().Version?.ToString(3) ?? "0";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    private readonly AgentConfig _cfg;
    private readonly HttpClient _http;
    private readonly Func<IShell> _shell;
    private readonly Action<string> _log;
    private long _appliedRevision = -1;
    private DateTime _lastFullApply = DateTime.MinValue;
    private AgentRelay? _appliedRelay;
    private bool _helloDone;

    public string Role { get; private set; } = "";

    public AgentRunner(AgentConfig cfg, HttpClient? http = null, Func<IShell>? shell = null, Action<string>? log = null)
    {
        _cfg = cfg;
        _http = http ?? new HttpClient { BaseAddress = new Uri(cfg.Api.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", cfg.Token);
        _shell = shell ?? (() => new LocalShell());
        _log = log ?? (m => Console.WriteLine(m));
    }

    /// <summary>Бесконечный цикл: состояние → применение → отчёт.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        _log($"Маяк-агент {Version}, API {_cfg.Api}");
        while (!ct.IsCancellationRequested)
        {
            int wait = 30;
            try
            {
                wait = await CycleAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log("Ошибка: " + ex.Message);
                wait = 30;
            }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(wait, 5, 600)), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Один проход. Возвращает, через сколько секунд прийти снова.</summary>
    public async Task<int> CycleAsync(CancellationToken ct)
    {
        if (!_helloDone) await HelloAsync(ct);
        var state = await _http.GetFromJsonAsync<AgentState>(AgentPaths.State, Json, ct) ?? throw new InvalidOperationException("API вернул пустое состояние");
        Role = state.Role;
        var report = Role == "entry" ? ApplyEntry(state) : ApplyExit(state);
        using var resp = await _http.PostAsJsonAsync(AgentPaths.Report, report, Json, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized) throw new InvalidOperationException("API не принимает токен агента — выдайте новый в админке");
        return state.PollSeconds;
    }

    private async Task HelloAsync(CancellationToken ct)
    {
        var hello = new AgentHello { Version = Version, Hostname = Environment.MachineName };
        try
        {
            using var shell = _shell();
            var server = new MayakServer(shell, PublicHost(shell));
            server.Connect();
            if (server.GetState() == ServerState.Running)
            {
                var snap = server.Load();
                var (awgPriv, xrayPriv) = server.ReadServerSecrets();
                hello.Identity = new AgentIdentity
                {
                    Awg = snap.Endpoint,
                    AwgServerPrivateKey = awgPriv,
                    Xray = snap.Xray,
                    XrayPrivateKey = xrayPriv,
                    Dns1 = snap.Db.Dns1,
                    Dns2 = snap.Db.Dns2,
                    Title = snap.Db.ServerTitle,
                };
                if (snap.Db.AllDevices.Any()) hello.Legacy = snap.Db;
                hello.ReservedIps = Reserved(snap, null);
            }
        }
        catch (MayakException ex)
        {
            _log("VPN на этом сервере не найден (" + ex.Message + ") — агент работает как вход или ждёт установки.");
        }

        using var resp = await _http.PostAsJsonAsync(AgentPaths.Hello, hello, Json, ct);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"API отклонил знакомство: {(int)resp.StatusCode}");
        var reply = await resp.Content.ReadFromJsonAsync<AgentHelloReply>(Json, ct);
        Role = reply?.Role ?? "";
        _log($"Сервер «{reply?.Name}» ({Role}) на связи с API" + (reply?.ImportedDevices > 0 ? $", перенесено устройств: {reply.ImportedDevices}" : ""));
        _helloDone = true;
    }

    private AgentReport ApplyExit(AgentState state)
    {
        var report = new AgentReport { AppliedRevision = _appliedRevision };
        using var shell = _shell();
        var server = new MayakServer(shell, PublicHost(shell));
        server.Log += m => _log(m);
        server.Connect();
        if (server.GetState() != ServerState.Running)
        {
            report.Error = "VPN на сервере не установлен или остановлен";
            return report;
        }

        var snap = server.Load();
        var users = AgentMapping.ToUsers(state);
        // Пропускаем применение, если ничего не менялось (но раз в 10 минут сверяемся всё равно).
        bool due = state.Revision != _appliedRevision || DateTime.UtcNow - _lastFullApply > TimeSpan.FromMinutes(10);
        if (due)
        {
            var wanted = users.SelectMany(u => u.Devices).Select(d => d.PublicKey).ToHashSet();
            int current = snap.Db.AllDevices.Count();
            int toRemove = snap.Db.AllDevices.Count(d => !wanted.Contains(d.PublicKey));
            if (!_cfg.AllowMassRemoval && current >= 4 && toRemove * 2 > current)
            {
                report.Error = $"API просит отозвать {toRemove} из {current} подключений — похоже на сбой, изменения не применены. " +
                               "Если это намеренно, включите allowMassRemoval в /etc/mayak/agent.json.";
                _log(report.Error);
            }
            else
            {
                var result = server.ApplyDesiredState(snap, users, state.DefaultDownMbps, state.DefaultUpMbps);
                report.Result = result;
                _appliedRevision = state.Revision;
                _lastFullApply = DateTime.UtcNow;
                report.AppliedRevision = state.Revision;
                if (result.Added > 0 || result.Removed > 0) _log($"Ревизия {state.Revision}: добавлено {result.Added}, отозвано {result.Removed}, всего {result.Total}");
            }
        }
        else
        {
            report.AppliedRevision = _appliedRevision;
        }

        report.Peers = snap.Stats.Values.Select(s => new AgentPeerStats
        {
            PublicKey = s.PublicKey,
            LatestHandshake = s.LatestHandshake,
            RxBytes = s.RxBytes,
            TxBytes = s.TxBytes,
        }).ToList();
        report.ReservedIps = Reserved(snap, users);
        report.Warnings = snap.Warnings;
        return report;
    }

    private AgentReport ApplyEntry(AgentState state)
    {
        var report = new AgentReport { AppliedRevision = state.Revision };
        using var shell = _shell();
        var relay = new RelayServer(shell);
        relay.Log += m => _log(m);
        relay.Connect();
        bool same = _appliedRelay != null && state.Relay != null && _appliedRelay.TargetHost == state.Relay.TargetHost &&
                    _appliedRelay.AwgPort == state.Relay.AwgPort && _appliedRelay.XrayPort == state.Relay.XrayPort;
        if (state.Relay == null)
        {
            if (_appliedRelay != null || relay.GetStatus().Installed)
            {
                relay.Remove();
                _appliedRelay = null;
            }
        }
        else if (!same || DateTime.UtcNow - _lastFullApply > TimeSpan.FromMinutes(10))
        {
            var unreachable = relay.Install(new RelayOptions
            {
                TargetHost = state.Relay.TargetHost,
                AwgPort = state.Relay.AwgPort,
                XrayPort = state.Relay.XrayPort,
                SshForwardPort = 0,
            });
            _appliedRelay = state.Relay;
            _lastFullApply = DateTime.UtcNow;
            if (unreachable.Count > 0)
                report.Warnings.Add($"Выход {state.Relay.TargetHost} недоступен с этого входа по TCP: {string.Join(", ", unreachable)}");
        }
        return report;
    }

    /// <summary>Адреса в подсети, занятые не устройствами из API: служебная учётка и подключения из AmneziaVPN.</summary>
    private static List<string> Reserved(ServerSnapshot snap, List<VpnUser>? users)
    {
        var mine = (users ?? new()).SelectMany(u => u.Devices).Select(d => d.Ip).ToHashSet();
        var list = snap.Foreign.Select(f => f.Ip).Where(ip => ip.Length > 0 && !mine.Contains(ip)).ToList();
        if (snap.Db.Probe is { AwgIp.Length: > 0 } p) list.Add(p.AwgIp);
        return list.Distinct().ToList();
    }

    private string PublicHost(IShell shell)
    {
        if (!string.IsNullOrWhiteSpace(_cfg.PublicHost)) return _cfg.PublicHost.Trim();
        var ip = shell.Run("hostname -I 2>/dev/null | awk '{print $1}'", TimeSpan.FromSeconds(5)).Output.Trim();
        return ip.Length > 0 ? ip : "127.0.0.1";
    }
}
