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
    /// <summary>Пробный режим: агент переносит людей в API и показывает, что изменил бы, но сервер не трогает.</summary>
    public bool DryRun { get; set; }
    /// <summary>Где агент хранит свои данные: какие устройства уже видел в API, резервные копии.</summary>
    public string StateDir { get; set; } = "/var/lib/mayak-agent";
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
    private bool _backupDone;
    private HashSet<string>? _seen;

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
        var state = await GetStateAsync(ct);
        Role = state.Role;
        AgentReport report;
        if (Role == "entry")
        {
            report = ApplyEntry(state);
        }
        else
        {
            // Устройства, которые появились на сервере мимо API (например, их добавил Маяк для Windows),
            // сначала переносятся в API — иначе агент принял бы их за удалённые.
            var unknown = UnknownLocalDevices(state);
            if (unknown != null)
            {
                await SendHelloAsync(new AgentHello { Version = Version, Hostname = Environment.MachineName, Legacy = unknown }, ct);
                state = await GetStateAsync(ct);
            }
            report = ApplyExit(state);
        }
        using var resp = await _http.PostAsJsonAsync(AgentPaths.Report, report, Json, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized) throw new InvalidOperationException("API не принимает токен агента — выдайте новый в админке");
        return state.PollSeconds;
    }

    private async Task<AgentState> GetStateAsync(CancellationToken ct) =>
        await _http.GetFromJsonAsync<AgentState>(AgentPaths.State, Json, ct) ?? throw new InvalidOperationException("API вернул пустое состояние");

    private string SeenPath => Path.Combine(_cfg.StateDir, "seen-devices.txt");

    /// <summary>Ключи устройств, которые агент хоть раз получал из API.</summary>
    private HashSet<string> Seen
    {
        get
        {
            if (_seen != null) return _seen;
            try { _seen = File.Exists(SeenPath) ? File.ReadAllLines(SeenPath).Where(l => l.Length > 0).ToHashSet() : new(); }
            catch (IOException) { _seen = new(); }
            return _seen;
        }
    }

    private void RememberSeen(IEnumerable<string> keys)
    {
        var before = Seen.Count;
        Seen.UnionWith(keys);
        if (Seen.Count == before && File.Exists(SeenPath)) return;
        Directory.CreateDirectory(_cfg.StateDir);
        File.WriteAllLines(SeenPath, Seen.OrderBy(k => k));
    }

    /// <summary>Устройства на сервере, которых нет в API и которые агент никогда там не видел. null — таких нет.</summary>
    private MayakDatabase? UnknownLocalDevices(AgentState state)
    {
        using var shell = _shell();
        var server = new MayakServer(shell, PublicHost(shell));
        server.Connect();
        if (server.GetState() != ServerState.Running) return null;
        var db = server.Load().Db;
        var inApi = state.Accounts.SelectMany(a => a.Devices).Select(d => d.PublicKey).ToHashSet();
        var unknownUsers = db.Users
            .Select(u => new VpnUser
            {
                Id = u.Id, Name = u.Name, Note = u.Note, Enabled = u.Enabled, CreatedAt = u.CreatedAt,
                Devices = u.Devices.Where(d => !inApi.Contains(d.PublicKey) && !Seen.Contains(d.PublicKey)).ToList(),
            })
            .Where(u => u.Devices.Count > 0)
            .ToList();
        if (unknownUsers.Count == 0) return null;
        _log($"На сервере есть устройства, которых нет в API ({unknownUsers.Sum(u => u.Devices.Count)}) — переношу их в API.");
        return new MayakDatabase { Users = unknownUsers, DefaultDownMbps = db.DefaultDownMbps, DefaultUpMbps = db.DefaultUpMbps };
    }

    private async Task<AgentHelloReply?> SendHelloAsync(AgentHello hello, CancellationToken ct)
    {
        using var resp = await _http.PostAsJsonAsync(AgentPaths.Hello, hello, Json, ct);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"API отклонил знакомство: {(int)resp.StatusCode}");
        return await resp.Content.ReadFromJsonAsync<AgentHelloReply>(Json, ct);
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
                // Устройства, которые агент уже получал из API, не переносим повторно:
                // если их там больше нет, значит их удалили намеренно.
                var legacyUsers = snap.Db.Users
                    .Select(u => new VpnUser { Id = u.Id, Name = u.Name, Note = u.Note, Enabled = u.Enabled, CreatedAt = u.CreatedAt, Devices = u.Devices.Where(d => !Seen.Contains(d.PublicKey)).ToList() })
                    .Where(u => u.Devices.Count > 0).ToList();
                if (legacyUsers.Count > 0)
                    hello.Legacy = new MayakDatabase { Users = legacyUsers, DefaultDownMbps = snap.Db.DefaultDownMbps, DefaultUpMbps = snap.Db.DefaultUpMbps, Dns1 = snap.Db.Dns1, Dns2 = snap.Db.Dns2, ServerTitle = snap.Db.ServerTitle };
                hello.ReservedIps = Reserved(snap, null);
            }
        }
        catch (MayakException ex)
        {
            _log("VPN на этом сервере не найден (" + ex.Message + ") — агент работает как вход или ждёт установки.");
        }

        var reply = await SendHelloAsync(hello, ct);
        Role = reply?.Role ?? "";
        _log($"Сервер «{reply?.Name}» ({Role}) на связи с API" + (reply?.ImportedDevices > 0 ? $", перенесено устройств: {reply.ImportedDevices}" : ""));
        _helloDone = true;
    }

    private AgentReport ApplyExit(AgentState state)
    {
        var report = new AgentReport { AppliedRevision = _appliedRevision, DryRun = _cfg.DryRun };
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
        KeepUnacknowledged(snap, users, report);
        // Пропускаем применение, если ничего не менялось (но раз в 10 минут сверяемся всё равно).
        bool due = state.Revision != _appliedRevision || DateTime.UtcNow - _lastFullApply > TimeSpan.FromMinutes(10);
        if (due)
        {
            var wanted = users.SelectMany(u => u.Devices).Select(d => d.PublicKey).ToHashSet();
            int current = snap.Db.AllDevices.Count();
            int toRemove = snap.Db.AllDevices.Count(d => !wanted.Contains(d.PublicKey));
            int toAdd = users.Where(u => u.Enabled).SelectMany(u => u.Devices).Count(d => d.Enabled && !snap.PeersOnServer.Contains(d.PublicKey));
            if (_cfg.DryRun)
            {
                report.Warnings.Add($"Пробный режим: агент добавил бы {toAdd} и отозвал бы {toRemove} подключений. Сервер не изменён.");
                _log(report.Warnings[^1]);
                if (toRemove > 0)
                    report.Warnings.Add("Отозвал бы: " + string.Join(", ", snap.Db.Users.SelectMany(u => u.Devices.Where(d => !wanted.Contains(d.PublicKey)).Select(d => $"{u.Name} / {d.Name}"))));
            }
            else if (!_cfg.AllowMassRemoval && current >= 4 && toRemove * 2 > current)
            {
                report.Error = $"API просит отозвать {toRemove} из {current} подключений — похоже на сбой, изменения не применены. " +
                               "Если это намеренно, включите allowMassRemoval в /etc/mayak/agent.json.";
                _log(report.Error);
            }
            else
            {
                if (!_backupDone)
                {
                    BackupServer(shell);
                    _backupDone = true;
                }
                var result = server.ApplyDesiredState(snap, users, state.DefaultDownMbps, state.DefaultUpMbps);
                RememberSeen(wanted);
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
        report.Warnings.AddRange(snap.Warnings);
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

    /// <summary>
    /// Главное правило безопасности: агент отзывает только те подключения, которые раньше получал из API.
    /// Всё, что есть на сервере, но API о нём не знает (не удалось перенести, конфликт адресов), остаётся как есть.
    /// </summary>
    private void KeepUnacknowledged(ServerSnapshot snap, List<VpnUser> users, AgentReport report)
    {
        var wanted = users.SelectMany(u => u.Devices).Select(d => d.PublicKey).ToHashSet();
        var kept = new List<string>();
        foreach (var u in snap.Db.Users)
        {
            var keep = u.Devices.Where(d => !wanted.Contains(d.PublicKey) && !Seen.Contains(d.PublicKey)).ToList();
            if (keep.Count == 0) continue;
            var target = users.FirstOrDefault(x => x.Id == u.Id);
            if (target == null)
            {
                target = new VpnUser { Id = u.Id, Name = u.Name, Note = u.Note, Enabled = u.Enabled, CreatedAt = u.CreatedAt };
                users.Add(target);
            }
            target.Devices.AddRange(keep);
            kept.AddRange(keep.Select(d => $"{u.Name} / {d.Name} ({d.Ip})"));
        }
        if (kept.Count > 0)
            report.Warnings.Add($"На сервере есть подключения, которых нет в API — оставлены без изменений ({kept.Count}): {string.Join(", ", kept)}");
    }

    /// <summary>Копия настроек VPN перед первым изменением после запуска агента — для отката вручную.</summary>
    private void BackupServer(IShell shell)
    {
        var dir = Path.Combine(_cfg.StateDir, "backup", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
        var r = shell.Run($"mkdir -p {SshConnection.Q(dir)} && " +
                          $"{shell.Sudo}docker cp {MayakServer.Container}:{MayakServer.AwgDir} {SshConnection.Q(dir + "/awg")} 2>&1; " +
                          $"{shell.Sudo}docker cp amnezia-xray:/opt/amnezia/xray {SshConnection.Q(dir + "/xray")} 2>/dev/null; " +
                          $"ls -d {SshConnection.Q(dir)}/* 2>/dev/null; " +
                          $"ls -1dt {SshConnection.Q(Path.Combine(_cfg.StateDir, "backup"))}/* | tail -n +11 | xargs -r rm -rf", TimeSpan.FromSeconds(60));
        _log(r.Output.Contains("/awg") ? $"Резервная копия настроек VPN: {dir}" : "Резервную копию сделать не удалось: " + SshConnection.Tail(r.Combined, 3));
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
