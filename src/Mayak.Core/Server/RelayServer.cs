namespace Mayak.Core.Server;

/// <summary>Что пересылать с входного сервера на основной.</summary>
public sealed class RelayOptions
{
    /// <summary>Адрес основного сервера (IP или домен), как до него достучаться из дата-центра входа.</summary>
    public string TargetHost { get; set; } = "";
    public int AwgPort { get; set; }
    public int? XrayPort { get; set; }
    /// <summary>Порт на входе, через который Маяк ходит по SSH к основному серверу (0 — не пробрасывать).</summary>
    /// <remarks>Старый способ управления через вход; теперь Маяк ходит SSH-туннелем (SshCredentials.Jump).</remarks>
    public int SshForwardPort { get; set; }
    public int TargetSshPort { get; set; } = 22;

    /// <summary>Дополнительные TCP-порты основного сервера, доступность которых проверить с входа (например, SSH).</summary>
    public List<int> CheckTcp { get; set; } = new();

    public string Forwards()
    {
        var list = new List<string> { $"udp:{AwgPort}:{AwgPort}" };
        if (XrayPort is int x)
        {
            list.Add($"tcp:{x}:{x}");
            list.Add($"udp:{x}:{x}");
        }
        if (SshForwardPort > 0) list.Add($"tcp:{SshForwardPort}:{TargetSshPort}");
        return string.Join(" ", list);
    }
}

public sealed record RelayStatus(bool Installed, string TargetHost, string Forwards, bool ServiceActive, int RuleCount);

/// <summary>Входной сервер каскада: только пересылка портов, без Docker и без ключей.</summary>
public sealed class RelayServer : IDisposable
{
    private readonly SshCredentials _creds;
    private readonly IShell _ssh;

    public event Action<string>? Log;
    public string? Fingerprint => _ssh.ServerFingerprint;

    public RelayServer(SshCredentials creds)
    {
        _creds = creds;
        _ssh = new SshConnection(creds);
    }

    /// <summary>Управление через готовую оболочку (агент на самом входе).</summary>
    public RelayServer(IShell shell, int ownSshPort = 22)
    {
        _creds = new SshCredentials { Host = "localhost", Port = ownSshPort };
        _ssh = shell;
    }

    private string S => _ssh.Sudo;
    private void Info(string m) => Log?.Invoke(m);

    public void Connect()
    {
        Info($"Подключение ко входному серверу {_creds.Host}:{_creds.Port}…");
        _ssh.Connect();
    }

    /// <summary>
    /// Настраивает пересылку. Возвращает порты основного сервера, недоступные с входа по TCP
    /// (признак того, что IP основного сервера блокируется и в этом дата-центре).
    /// </summary>
    public IReadOnlyList<int> Install(RelayOptions opt, Action<string>? step = null)
    {
        step?.Invoke("Настройка пересылки на входном сервере");
        Info("▸ Настройка пересылки: " + opt.Forwards());
        var relayScript = _ssh.UploadTemp(ScriptLibrary.Load("relay.sh"), ".sh");
        try
        {
            var vars = new Dictionary<string, string>
            {
                ["SUDO"] = S.Trim(),
                ["TARGET_HOST"] = opt.TargetHost,
                ["FORWARDS"] = opt.Forwards(),
                ["OWN_SSH_PORT"] = _creds.Port.ToString(),
                ["RELAY_SCRIPT"] = relayScript,
                ["CHECK_TCP"] = string.Join(" ", opt.CheckTcp),
            };
            var r = _ssh.RunScript(ScriptLibrary.Load("relay_install.sh", vars), TimeSpan.FromMinutes(5));
            if (!r.Output.Contains("MAYAK_OK"))
            {
                var err = r.Combined.Split('\n').FirstOrDefault(l => l.Contains("MAYAK_ERROR"))?.Replace("MAYAK_ERROR:", "").Trim();
                throw new MayakException("Входной сервер: " + (err ?? "ошибка настройки") + "\n" + SshConnection.Tail(r.Combined));
            }

            var unreachable = new List<int>();
            foreach (var line in r.Output.Split('\n').Where(l => l.StartsWith("MAYAK_REACH:")))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4 && parts[3] == "fail" && int.TryParse(parts[2], out var port)) unreachable.Add(port);
            }
            Info(unreachable.Count == 0
                ? "Вход видит основной сервер, пересылка включена."
                : "Внимание: с входного сервера недоступны TCP-порты основного: " + string.Join(", ", unreachable));
            return unreachable;
        }
        finally
        {
            _ssh.Run($"rm -f {SshConnection.Q(relayScript)}");
        }
    }

    public void Remove()
    {
        _ssh.Run($"{S}systemctl disable --now mayak-relay.service 2>/dev/null; {S}/usr/local/sbin/mayak-relay.sh remove 2>/dev/null; " +
                 $"{S}rm -f /etc/systemd/system/mayak-relay.service /usr/local/sbin/mayak-relay.sh /etc/mayak-relay.conf /etc/sysctl.d/99-mayak-relay.conf; {S}systemctl daemon-reload");
        Info("Пересылка на входном сервере снята.");
    }

    public RelayStatus GetStatus()
    {
        var conf = _ssh.Run($"{S}cat /etc/mayak-relay.conf 2>/dev/null").Output;
        string Get(string key)
        {
            var line = conf.Split('\n').FirstOrDefault(l => l.StartsWith(key + "="));
            return line == null ? "" : line[(key.Length + 1)..].Trim().Trim('"');
        }
        var active = _ssh.Run($"{S}systemctl is-active mayak-relay.service 2>/dev/null").Output.Trim() == "active";
        var rules = _ssh.Run($"{S}iptables -t nat -S MAYAK_PRE 2>/dev/null | grep -c DNAT").Output.Trim();
        return new RelayStatus(conf.Length > 0, Get("TARGET_HOST"), Get("FORWARDS"), active, int.TryParse(rules, out var n) ? n : 0);
    }

    /// <summary>Проверяет с входа, доступен ли адрес (TCP-порты и контрольные адреса).</summary>
    public Probe.VantageResult CheckAddress(string name, string host, IReadOnlyList<int> ports)
    {
        var r = _ssh.RunScript(Probe.AddressCheck.RemoteScript(host, ports), TimeSpan.FromSeconds(60));
        return Probe.AddressCheck.ParseRemote(name, host, r.Output);
    }

        public bool IsAlive() => _ssh.IsAlive();

    public void Dispose() => _ssh.Dispose();
}
