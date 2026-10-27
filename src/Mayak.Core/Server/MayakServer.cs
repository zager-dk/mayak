using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;
using Mayak.Core.Models;

namespace Mayak.Core.Server;

public enum ServerState
{
    /// <summary>Docker не установлен — сервер чистый.</summary>
    Clean,
    /// <summary>Docker есть, контейнера AmneziaWG нет.</summary>
    DockerOnly,
    /// <summary>Контейнер есть, но остановлен.</summary>
    Stopped,
    /// <summary>Работает.</summary>
    Running,
}

public sealed class InstallOptions
{
    public int Port { get; set; } = RandomPort();
    public AwgProtocolVersion Version { get; set; } = AwgProtocolVersion.V2;
    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "1.0.0.1";
    public string Title { get; set; } = "Маяк VPN";
    public string SubnetAddress { get; set; } = "10.8.1.0";
    public int SubnetCidr { get; set; } = 24;
    public int DefaultDownMbps { get; set; } = 35;
    public int DefaultUpMbps { get; set; } = 35;

    /// <summary>Сразу поставить Xray (VLESS + Reality + XHTTP) вторым протоколом.</summary>
    public bool InstallXray { get; set; } = true;
    public XrayInstallOptions Xray { get; set; } = new();

    /// <summary>Случайный порт 30000–49999, как AmneziaVPN: стандартные порты чаще блокируют.</summary>
    public static int RandomPort() => System.Security.Cryptography.RandomNumberGenerator.GetInt32(30000, 50000);
}

/// <summary>Состояние сервера, прочитанное за одно подключение.</summary>
/// <summary>Итог синхронизации с API: сколько пиров добавлено и отозвано, сколько всего на сервере.</summary>
public sealed record DesiredStateResult(int Added, int Removed, int Total);

/// <summary>Результат выдачи по списку: устройство и было ли оно создано сейчас.</summary>
public sealed record GrantItem(VpnUser User, VpnDevice Device, bool Created);

public sealed class ServerSnapshot
{
    public ServerEndpoint Endpoint { get; set; } = new();
    public MayakDatabase Db { get; set; } = new();
    public Dictionary<string, PeerStats> Stats { get; set; } = new();
    public HashSet<string> PeersOnServer { get; set; } = new();
    public List<ForeignPeer> Foreign { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public string ServerAddress { get; set; } = "10.8.1.0";

    /// <summary>Xray на сервере (null — не установлен).</summary>
    public XrayEndpoint? Xray { get; set; }
    public ServerState XrayState { get; set; } = ServerState.DockerOnly;

    /// <summary>Устройство числится активным, но его нет в конфиге сервера (отозвано вне Маяка).</summary>
    public bool IsMissingOnServer(VpnDevice d) => d.Enabled && !PeersOnServer.Contains(d.PublicKey);

    public PeerStats? StatsFor(VpnDevice d) => Stats.TryGetValue(d.PublicKey, out var s) ? s : null;
}

/// <summary>
/// Управление сервером Маяка. Раскладка файлов совпадает с AmneziaVPN (контейнер amnezia-awg2),
/// поэтому сервер продолжает открываться и в официальном приложении.
/// Все методы синхронные (SSH) — вызывайте их из фонового потока.
/// </summary>
public sealed partial class MayakServer : IDisposable
{
    public const string Container = "amnezia-awg2";
    public const string AwgDir = "/opt/amnezia/awg";
    public const string ConfPath = AwgDir + "/awg0.conf";
    public const string DbPath = AwgDir + "/mayak.json";
    public const string LimitsPath = AwgDir + "/mayak_limits";
    public const string TcScriptPath = AwgDir + "/mayak_tc.sh";
    public const string ClientsTablePath = AwgDir + "/clientsTable";
    public const string ServerPrivKeyPath = AwgDir + "/wireguard_server_private_key.key";
    public const string ServerPubKeyPath = AwgDir + "/wireguard_server_public_key.key";
    public const string PskPath = AwgDir + "/wireguard_psk.key";
    public const string StartScriptPath = "/opt/amnezia/start.sh";
    public const string DockerfileFolder = "/opt/amnezia/amnezia-awg2";

    private static readonly JsonSerializerOptions DbJson = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly SshCredentials _creds;
    private readonly IShell _ssh;

    public event Action<string>? Log;

    public string? Fingerprint => _ssh.ServerFingerprint;
    public string? JumpFingerprint => _ssh.JumpFingerprint;

    public MayakServer(SshCredentials creds)
    {
        _creds = creds;
        _ssh = new SshConnection(creds);
    }

    /// <summary>Управление через готовую оболочку (агент на самом сервере). publicHost — адрес для клиентов по умолчанию.</summary>
    public MayakServer(IShell shell, string publicHost)
    {
        _creds = new SshCredentials { Host = publicHost };
        _ssh = shell;
    }

    public void Connect()
    {
        if (_ssh is LocalShell) Info("Работаю на этом сервере.");
        else Info($"Подключение к {_creds.Host}:{_creds.Port} как {_creds.User}" + (_creds.Jump is { } j ? $" через {j.Host}…" : "…"));
        _ssh.Connect();
        Info(_ssh.IsRoot ? "Вход выполнен (root)." : "Вход выполнен (sudo без пароля).");
    }

    private string S => _ssh.Sudo;

    /// <summary>SSH-сессия ещё работает.</summary>
    public bool IsAlive() => _ssh.IsAlive();

    private void Info(string msg) => Log?.Invoke(msg);

    // ───────────────────────────── Состояние ─────────────────────────────

    public ServerState GetState()
    {
        var docker = _ssh.Run("command -v docker >/dev/null 2>&1 && echo yes || echo no").Output.Trim();
        if (docker != "yes") return ServerState.Clean;
        var state = _ssh.Run($"{S}docker inspect -f '{{{{.State.Status}}}}' {Container} 2>/dev/null").Output.Trim();
        return state switch
        {
            "" => ServerState.DockerOnly,
            "running" => ServerState.Running,
            _ => ServerState.Stopped,
        };
    }

    public void StartContainer()
    {
        _ssh.RunChecked($"{S}docker start {Container}", "Запуск контейнера");
        Thread.Sleep(2000);
    }

    // ───────────────────────────── Установка ─────────────────────────────

    /// <summary>Полная установка AmneziaWG с нуля. reinstall=true удалит существующий контейнер со всеми ключами.</summary>
    public void Install(InstallOptions opt, bool reinstall, Action<string>? step = null)
    {
        void Step(string s) { step?.Invoke(s); Info("▸ " + s); }

        Step("Проверка сервера");
        var arch = _ssh.Run("uname -m").Output.Trim();
        if (arch is not ("x86_64" or "aarch64" or "arm64"))
            Info($"Внимание: архитектура {arch} не проверялась, образ может не собраться.");

        var state = GetState();
        if (state is ServerState.Running or ServerState.Stopped)
        {
            if (!reinstall)
                throw new MayakException("На сервере уже установлен AmneziaWG. Подключитесь к нему или выберите переустановку.");
            Step("Удаление старого контейнера");
            _ssh.Run($"{S}docker stop {Container}; {S}docker rm -fv {Container}; {S}docker rmi {Container}", TimeSpan.FromMinutes(3));
        }

        var portBusy = _ssh.Run($"({S}ss -lun 2>/dev/null || {S}netstat -lun 2>/dev/null) | grep -E '[:.]{opt.Port}\\s' >/dev/null && echo busy || echo free").Output.Trim();
        if (portBusy == "busy")
            throw new MayakException($"UDP-порт {opt.Port} уже занят на сервере. Выберите другой.");

        Step("Установка Docker (1–3 минуты)");
        var vars = new Dictionary<string, string> { ["SUDO"] = S.Trim(), ["DOCKERFILE_FOLDER"] = DockerfileFolder };
        ExpectOk(_ssh.RunScript(ScriptLibrary.Load("install_docker.sh", vars), TimeSpan.FromMinutes(15)), "Установка Docker");

        Step("Подготовка сети и файрвола");
        ExpectOk(_ssh.RunScript(ScriptLibrary.Load("prepare_host.sh", vars), TimeSpan.FromMinutes(3)), "Подготовка сервера");

        Step("Сборка контейнера AmneziaWG (2–5 минут)");
        _ssh.WriteHostFile(ScriptLibrary.Load("Dockerfile"), DockerfileFolder + "/Dockerfile");
        var build = _ssh.Run($"{S}docker build --no-cache --pull -t {Container} {DockerfileFolder} 2>&1", TimeSpan.FromMinutes(25));
        if (!build.Ok)
            throw new MayakException("Не удалось собрать контейнер. Частая причина — лимит скачиваний Docker Hub, попробуйте позже.\n" + SshConnection.Tail(build.Combined));

        Step("Запуск контейнера");
        _ssh.RunChecked(
            $"{S}docker run -d --log-driver none --restart always --privileged " +
            $"--cap-add=NET_ADMIN --cap-add=SYS_MODULE -p {opt.Port}:{opt.Port}/udp " +
            $"-v /lib/modules:/lib/modules --sysctl=\"net.ipv4.conf.all.src_valid_mark=1\" " +
            $"--name {Container} {Container}", "Запуск контейнера");
        _ssh.Run($"{S}docker network connect amnezia-dns-net {Container}");

        Step("Генерация ключей и конфигурации");
        var (serverPriv, serverPub) = Curve25519.GenerateKeyPair();
        var psk = Curve25519.GeneratePresharedKey();
        var parameters = AwgParameters.Generate(opt.Version);

        var conf = new StringBuilder();
        conf.Append("[Interface]\n");
        conf.Append($"PrivateKey = {serverPriv}\n");
        conf.Append($"Address = {opt.SubnetAddress}/{opt.SubnetCidr}\n");
        conf.Append($"ListenPort = {opt.Port}\n");
        foreach (var line in parameters.ServerInterfaceLines()) conf.Append(line).Append('\n');
        conf.Append('\n');

        ExecContainer($"mkdir -p {AwgDir}");
        WriteContainerFile(ServerPrivKeyPath, serverPriv + "\n", "600");
        WriteContainerFile(ServerPubKeyPath, serverPub + "\n", "644");
        WriteContainerFile(PskPath, psk + "\n", "600");
        WriteContainerFile(ConfPath, conf.ToString(), "600");
        WriteContainerFile(ClientsTablePath, "[]", "644");

        var startVars = new Dictionary<string, string> { ["SUBNET_IP"] = opt.SubnetAddress, ["SUBNET_CIDR"] = opt.SubnetCidr.ToString() };
        WriteContainerFile(StartScriptPath, ScriptLibrary.Load("start.sh", startVars), "755");
        WriteContainerFile(TcScriptPath, ScriptLibrary.Load("mayak_tc.sh"), "755");
        WriteContainerFile(LimitsPath, "", "644");

        var db = new MayakDatabase
        {
            ServerTitle = opt.Title,
            Dns1 = opt.Dns1,
            Dns2 = opt.Dns2,
            DefaultDownMbps = opt.DefaultDownMbps,
            DefaultUpMbps = opt.DefaultUpMbps,
        };
        WriteDatabaseFile(db);

        Step("Перезапуск и проверка");
        _ssh.RunChecked($"{S}docker restart {Container}", "Перезапуск контейнера");
        Thread.Sleep(3000);
        var show = ExecContainer("awg show awg0");
        if (!show.Ok)
            throw new MayakException("Контейнер запущен, но интерфейс awg0 не поднялся:\n" + SshConnection.Tail(show.Combined));

        Info($"Готово: AmneziaWG {parameters.ProtocolVersionString}, UDP-порт {opt.Port}. Не забудьте открыть этот порт в панели хостинга, если там есть файрвол.");
    }

    /// <summary>Удаляет VPN с сервера полностью (контейнер, образ, ключи).</summary>
    public void Uninstall()
    {
        Info("Удаление контейнера и образа…");
        _ssh.Run($"{S}docker stop {Container}; {S}docker rm -fv {Container}; {S}docker rmi {Container}; {S}rm -rf {DockerfileFolder}", TimeSpan.FromMinutes(3));
        Info("VPN удалён с сервера.");
    }

    // ───────────────────────────── Чтение состояния ─────────────────────────────

    public ServerSnapshot Load()
    {
        var snap = new ServerSnapshot();

        var confText = ReadContainerFile(ConfPath)
                       ?? throw new MayakException($"Не найден {ConfPath}. Сервер не настроен — выполните установку.");
        var conf = AwgConfigFile.Parse(confText);

        var serverPub = ReadContainerFile(ServerPubKeyPath)?.Trim();
        if (string.IsNullOrEmpty(serverPub))
        {
            var priv = conf.GetInterfaceValue("PrivateKey");
            serverPub = priv != null ? Curve25519.PublicKeyFromPrivate(priv) : throw new MayakException("Не найден ключ сервера.");
        }
        var psk = ReadContainerFile(PskPath)?.Trim() ?? "";

        var address = conf.GetInterfaceValue("Address") ?? "10.8.1.0/24";
        var addrParts = address.Split(',')[0].Trim().Split('/');
        snap.ServerAddress = addrParts[0];
        var cidr = addrParts.Length > 1 ? addrParts[1] : "24";
        var (net, _) = IpAllocator.Range(addrParts[0], int.Parse(cidr));

        snap.Db = ReadDatabase();
        snap.Endpoint = new ServerEndpoint
        {
            Host = string.IsNullOrWhiteSpace(snap.Db.EndpointHost) ? _creds.Host : snap.Db.EndpointHost.Trim(),
            Port = int.TryParse(conf.GetInterfaceValue("ListenPort"), out var port) ? port : 0,
            ServerPublicKey = serverPub,
            PresharedKey = psk,
            SubnetAddress = IpAllocator.FromUInt(net),
            SubnetCidr = cidr,
            Parameters = AwgParameters.FromServerConfig(conf),
        };

        if (string.IsNullOrEmpty(psk))
            snap.Warnings.Add("На сервере нет общего PSK-ключа — новые устройства получат его, но старые конфиги Amnezia могут не совпасть.");

        snap.PeersOnServer = conf.Peers.Select(p => p.PublicKey).ToHashSet();

        var names = ReadClientsTableNames();
        var ours = snap.Db.AllDevices.Select(d => d.PublicKey).ToHashSet();
        if (snap.Db.Probe != null) ours.Add(snap.Db.Probe.AwgPublicKey);
        foreach (var peer in conf.Peers.Where(p => !ours.Contains(p.PublicKey)))
        {
            snap.Foreign.Add(new ForeignPeer
            {
                PublicKey = peer.PublicKey,
                Ip = peer.Ip ?? "",
                Name = names.TryGetValue(peer.PublicKey, out var n) ? n : "(без имени)",
            });
        }

        snap.Stats = ReadStats();
        LoadXray(snap);

        foreach (var d in snap.Db.AllDevices.Where(snap.IsMissingOnServer))
        {
            var user = snap.Db.FindUserByDevice(d);
            if (user is { Enabled: true })
                snap.Warnings.Add($"Устройство «{user.Name} / {d.Name}» удалено с сервера вне Маяка (например, в AmneziaVPN). Включите его заново или удалите.");
        }

        return snap;
    }

    private Dictionary<string, PeerStats> ReadStats()
    {
        var result = new Dictionary<string, PeerStats>();
        var r = ExecContainer("awg show awg0 dump");
        if (!r.Ok) return result;
        var lines = r.Output.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines.Skip(1))
        {
            var f = line.Split('\t');
            if (f.Length < 7) continue;
            var st = new PeerStats
            {
                PublicKey = f[0],
                Endpoint = f[2] == "(none)" ? null : f[2],
            };
            if (long.TryParse(f[4], out var hs) && hs > 0)
                st.LatestHandshake = DateTimeOffset.FromUnixTimeSeconds(hs).UtcDateTime;
            long.TryParse(f[5], out var rx);
            long.TryParse(f[6], out var tx);
            st.RxBytes = rx;
            st.TxBytes = tx;
            result[st.PublicKey] = st;
        }
        return result;
    }

    // ───────────────────────────── Пользователи и устройства ─────────────────────────────

    /// <summary>Создаёт устройство: ключи, IP, пир на сервере, лимиты.</summary>
    public VpnDevice AddDevice(ServerSnapshot snap, VpnUser user, string name, DeviceKind kind, int downMbps, int upMbps)
    {
        var conf = ReadConf();
        var used = conf.Peers.Select(p => p.Ip ?? "").Concat(snap.Db.AllDevices.Select(d => d.Ip));
        var ip = IpAllocator.Next(snap.Endpoint.SubnetAddress, int.Parse(snap.Endpoint.SubnetCidr), snap.ServerAddress, used);
        var (priv, pub) = Curve25519.GenerateKeyPair();

        var device = new VpnDevice
        {
            Name = name,
            Kind = kind,
            PrivateKey = priv,
            PublicKey = pub,
            Ip = ip,
            DownMbps = downMbps,
            UpMbps = upMbps,
            Enabled = true,
        };

        if (user.Enabled)
        {
            conf.AddPeer(pub, snap.Endpoint.PresharedKey, ip);
            WriteConfAndSync(conf);
            snap.PeersOnServer.Add(pub);
        }

        user.Devices.Add(device);
        Commit(snap);
        Info($"Добавлено устройство «{user.Name} / {name}» ({ip}).");
        return device;
    }

    /// <summary>
    /// Выдаёт доступ людям из постоянного списка: находит или создаёт пользователя (по связи PersonId, иначе по имени)
    /// и недостающие устройства (по TemplateId, иначе по имени и типу). Все новые пиры пишутся одним обновлением конфига.
    /// </summary>
    public IReadOnlyList<GrantItem> GrantPeople(ServerSnapshot snap, IEnumerable<Person> people)
    {
        var conf = ReadConf();
        var used = new HashSet<string>(conf.Peers.Select(p => p.Ip ?? "").Concat(snap.Db.AllDevices.Select(d => d.Ip)));
        if (snap.Db.Probe is { AwgIp: { Length: > 0 } probeIp }) used.Add(probeIp);
        var result = new List<GrantItem>();
        bool confChanged = false;

        foreach (var person in people)
        {
            var name = person.Name.Trim();
            if (name.Length == 0) continue;
            var user = FindUser(snap.Db, person);
            if (user == null)
            {
                user = new VpnUser { Name = name, Note = person.Note, PersonId = person.Id };
                snap.Db.Users.Add(user);
                Info($"Создан пользователь «{name}».");
            }
            user.PersonId = person.Id;

            foreach (var t in person.Devices)
            {
                var existing = FindDevice(user, t);
                if (existing != null)
                {
                    existing.TemplateId = t.Id;
                    result.Add(new GrantItem(user, existing, false));
                    continue;
                }
                var ip = IpAllocator.Next(snap.Endpoint.SubnetAddress, int.Parse(snap.Endpoint.SubnetCidr), snap.ServerAddress, used);
                used.Add(ip);
                var (priv, pub) = Curve25519.GenerateKeyPair();
                var device = new VpnDevice
                {
                    Name = t.Name.Trim().Length == 0 ? t.Kind.Title() : t.Name.Trim(),
                    Kind = t.Kind,
                    PrivateKey = priv,
                    PublicKey = pub,
                    Ip = ip,
                    DownMbps = t.DownMbps ?? snap.Db.DefaultDownMbps,
                    UpMbps = t.UpMbps ?? snap.Db.DefaultUpMbps,
                    Enabled = true,
                    TemplateId = t.Id,
                };
                if (user.Enabled)
                {
                    conf.AddPeer(pub, snap.Endpoint.PresharedKey, ip);
                    snap.PeersOnServer.Add(pub);
                    confChanged = true;
                }
                user.Devices.Add(device);
                result.Add(new GrantItem(user, device, true));
                Info($"Добавлено устройство «{user.Name} / {device.Name}» ({ip}).");
            }
        }

        if (confChanged) WriteConfAndSync(conf);
        Commit(snap);
        return result;
    }

    /// <summary>Пользователь сервера, соответствующий человеку из списка.</summary>
    public static VpnUser? FindUser(MayakDatabase db, Person person)
    {
        bool SameName(VpnUser u) => string.Equals(u.Name.Trim(), person.Name.Trim(), StringComparison.CurrentCultureIgnoreCase);
        return db.Users.FirstOrDefault(u => u.PersonId == person.Id)
               ?? db.Users.FirstOrDefault(u => u.PersonId == null && SameName(u))
               ?? db.Users.FirstOrDefault(SameName);
    }

    /// <summary>Устройство пользователя, соответствующее шаблону из списка.</summary>
    public static VpnDevice? FindDevice(VpnUser user, PersonDevice t)
    {
        bool Same(VpnDevice d) => d.Kind == t.Kind && string.Equals(d.Name.Trim(), t.Name.Trim(), StringComparison.CurrentCultureIgnoreCase);
        return user.Devices.FirstOrDefault(d => d.TemplateId == t.Id)
               ?? user.Devices.FirstOrDefault(d => d.TemplateId == null && Same(d))
               ?? user.Devices.FirstOrDefault(Same);
    }

    public void RemoveDevice(ServerSnapshot snap, VpnUser user, VpnDevice device)
    {
        var conf = ReadConf();
        if (conf.RemovePeer(device.PublicKey))
            WriteConfAndSync(conf);
        snap.PeersOnServer.Remove(device.PublicKey);
        user.Devices.Remove(device);
        Commit(snap);
        Info($"Устройство «{user.Name} / {device.Name}» удалено, доступ отозван.");
    }

    public void RemoveUser(ServerSnapshot snap, VpnUser user)
    {
        var conf = ReadConf();
        bool changed = false;
        foreach (var d in user.Devices)
        {
            changed |= conf.RemovePeer(d.PublicKey);
            snap.PeersOnServer.Remove(d.PublicKey);
        }
        if (changed) WriteConfAndSync(conf);
        snap.Db.Users.Remove(user);
        Commit(snap);
        Info($"Пользователь «{user.Name}» удалён, доступ на всех устройствах отозван.");
    }

    /// <summary>Включает/выключает доступ устройства без потери ключей.</summary>
    public void SetDeviceEnabled(ServerSnapshot snap, VpnUser user, VpnDevice device, bool enabled)
    {
        device.Enabled = enabled;
        SyncPeers(snap);
        Commit(snap);
        Info($"Устройство «{user.Name} / {device.Name}»: доступ {(enabled ? "включён" : "приостановлен")}.");
    }

    /// <summary>Включает/выключает все устройства пользователя.</summary>
    public void SetUserEnabled(ServerSnapshot snap, VpnUser user, bool enabled)
    {
        user.Enabled = enabled;
        SyncPeers(snap);
        Commit(snap);
        Info($"Пользователь «{user.Name}»: доступ {(enabled ? "включён" : "приостановлен")}.");
    }

    /// <summary>Сохраняет изменения имён, лимитов и настроек.</summary>
    public void Save(ServerSnapshot snap)
    {
        Commit(snap);
        Info("Изменения сохранены на сервере.");
    }

    /// <summary>Отзывает чужое подключение (созданное в AmneziaVPN).</summary>
    public void RevokeForeign(ServerSnapshot snap, ForeignPeer peer)
    {
        var conf = ReadConf();
        if (conf.RemovePeer(peer.PublicKey)) WriteConfAndSync(conf);
        snap.Foreign.Remove(peer);
        snap.PeersOnServer.Remove(peer.PublicKey);
        RemoveFromClientsTable(peer.PublicKey);
        Info($"Подключение «{peer.Name}» ({peer.Ip}) отозвано.");
    }

    /// <summary>
    /// Привязывает чужое подключение к пользователю, чтобы видеть его статистику и задать лимит.
    /// Выгрузить для него файл нельзя — приватного ключа на сервере нет.
    /// </summary>
    public VpnDevice AdoptForeign(ServerSnapshot snap, ForeignPeer peer, VpnUser user, DeviceKind kind)
    {
        var device = new VpnDevice
        {
            Name = peer.Name,
            Kind = kind,
            PublicKey = peer.PublicKey,
            Ip = peer.Ip,
            DownMbps = snap.Db.DefaultDownMbps,
            UpMbps = snap.Db.DefaultUpMbps,
        };
        user.Devices.Add(device);
        snap.Foreign.Remove(peer);
        Commit(snap);
        Info($"Подключение «{peer.Name}» привязано к пользователю «{user.Name}».");
        return device;
    }

    /// <summary>
    /// Приводит список пиров на сервере к базе: активные устройства есть, выключенные — убраны.
    /// Чужие пиры не трогает.
    /// </summary>
    public void SyncPeers(ServerSnapshot snap)
    {
        var conf = ReadConf();
        bool changed = false;
        foreach (var user in snap.Db.Users)
        {
            foreach (var d in user.Devices)
            {
                bool shouldBe = user.Enabled && d.Enabled;
                bool present = conf.HasPeer(d.PublicKey);
                if (shouldBe && !present && !string.IsNullOrEmpty(d.Ip))
                {
                    conf.AddPeer(d.PublicKey, snap.Endpoint.PresharedKey, d.Ip);
                    changed = true;
                }
                else if (!shouldBe && present)
                {
                    conf.RemovePeer(d.PublicKey);
                    changed = true;
                }
            }
        }
        if (changed) WriteConfAndSync(conf);
        snap.PeersOnServer = conf.Peers.Select(p => p.PublicKey).ToHashSet();
    }

    /// <summary>
    /// Приводит сервер к состоянию, присланному API: пользователи и устройства заменяются целиком,
    /// пиры удалённых устройств отзываются, новые добавляются, лимиты и Xray обновляются.
    /// Служебная учётка проверки и подключения, созданные не Маяком, не трогаются.
    /// </summary>
    public DesiredStateResult ApplyDesiredState(ServerSnapshot snap, IReadOnlyList<VpnUser> users, int defaultDownMbps, int defaultUpMbps)
    {
        var wanted = users.SelectMany(u => u.Devices).Select(d => d.PublicKey).ToHashSet();
        var gone = snap.Db.AllDevices.Where(d => !wanted.Contains(d.PublicKey)).Select(d => d.PublicKey).ToList();

        var conf = ReadConf();
        int removed = 0;
        foreach (var key in gone)
            if (conf.RemovePeer(key)) removed++;
        if (removed > 0) WriteConfAndSync(conf);
        foreach (var key in gone) RemoveFromClientsTable(key);

        var before = conf.Peers.Select(p => p.PublicKey).ToHashSet();
        snap.Db.Users = users.ToList();
        snap.Db.DefaultDownMbps = defaultDownMbps;
        snap.Db.DefaultUpMbps = defaultUpMbps;
        SyncPeers(snap);
        Commit(snap);
        int added = snap.PeersOnServer.Count(k => !before.Contains(k));
        return new DesiredStateResult(added, removed, snap.PeersOnServer.Count);
    }

    /// <summary>База + clientsTable + лимиты.</summary>
    private void Commit(ServerSnapshot snap)
    {
        if (snap.Xray != null) EnsureXrayIds(snap.Db);
        WriteDatabaseFile(snap.Db);
        SyncClientsTable(snap);
        ApplyLimits(snap);
        if (snap.Xray != null) SyncXrayClients(snap);
    }

    // ───────────────────────────── Лимиты скорости ─────────────────────────────

    public void ApplyLimits(ServerSnapshot snap)
    {
        EnsureTooling();
        int cidr = int.Parse(snap.Endpoint.SubnetCidr);
        var sb = new StringBuilder();
        sb.Append("# Mayak VPN: <ip> <down kbit> <up kbit> <tc classid hex>\n");
        foreach (var user in snap.Db.Users.Where(u => u.Enabled))
        {
            foreach (var d in user.Devices.Where(d => d.Enabled && !string.IsNullOrEmpty(d.Ip)))
            {
                if (d.DownMbps <= 0 && d.UpMbps <= 0) continue;
                var cls = IpAllocator.TcClassId(snap.Endpoint.SubnetAddress, cidr, d.Ip);
                sb.Append($"{d.Ip} {Math.Max(0, d.DownMbps) * 1000} {Math.Max(0, d.UpMbps) * 1000} {cls}\n");
            }
        }
        WriteContainerFile(LimitsPath, sb.ToString(), "644");
        var r = ExecContainer(TcScriptPath);
        foreach (var line in r.Combined.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains("MAYAK_WARN") || line.Contains("MAYAK_ERROR"))
                Info("Лимиты: " + line.Replace("MAYAK_WARN:", "").Replace("MAYAK_ERROR:", "").Trim());
        }
        if (!r.Ok && r.ExitCode != 1)
            Info("Лимиты скорости не применены: " + SshConnection.Tail(r.Combined, 3));
    }

    private bool _toolingChecked;

    /// <summary>
    /// Для серверов, установленных официальным AmneziaVPN: ставит tc, кладёт mayak_tc.sh
    /// и добавляет его вызов в start.sh, чтобы лимиты переживали перезапуск.
    /// </summary>
    private void EnsureTooling()
    {
        if (_toolingChecked) return;
        if (!ExecContainer("command -v tc").Ok)
        {
            Info("Устанавливаю iproute2 (tc) в контейнер…");
            var r = ExecContainer("apk add --no-cache iproute2", TimeSpan.FromMinutes(3));
            if (!r.Ok) Info("Не удалось установить iproute2: " + SshConnection.Tail(r.Combined, 3));
        }
        WriteContainerFile(TcScriptPath, ScriptLibrary.Load("mayak_tc.sh"), "755");

        var start = ReadContainerFile(StartScriptPath) ?? "";
        if (start.Length > 0 && !start.Contains("mayak_tc.sh"))
        {
            const string hook = "# Mayak VPN: speed limits\nif [ -x /opt/amnezia/awg/mayak_tc.sh ]; then /opt/amnezia/awg/mayak_tc.sh; fi\n\n";
            var idx = start.LastIndexOf("tail -f /dev/null", StringComparison.Ordinal);
            start = idx >= 0 ? start.Insert(idx, hook) : start + "\n" + hook;
            WriteContainerFile(StartScriptPath, start, "755");
            Info("В start.sh добавлен запуск лимитов скорости.");
        }
        _toolingChecked = true;
    }

    // ───────────────────────────── Настройки ─────────────────────────────

    /// <summary>Перезапуск контейнера (переприменяет всё с нуля).</summary>
    public void RestartContainer()
    {
        _ssh.RunChecked($"{S}docker restart {Container}", "Перезапуск контейнера");
        Thread.Sleep(3000);
        Info("Контейнер перезапущен.");
    }

    // ───────────────────────────── База и clientsTable ─────────────────────────────

    private MayakDatabase ReadDatabase()
    {
        var text = ReadContainerFile(DbPath);
        if (string.IsNullOrWhiteSpace(text)) return new MayakDatabase();
        try
        {
            return JsonSerializer.Deserialize<MayakDatabase>(text, DbJson) ?? new MayakDatabase();
        }
        catch (JsonException ex)
        {
            throw new MayakException($"Файл {DbPath} повреждён: {ex.Message}");
        }
    }

    private void WriteDatabaseFile(MayakDatabase db)
    {
        var json = JsonSerializer.Serialize(db, DbJson);
        WriteContainerFile(DbPath, json, "600");
    }

    private Dictionary<string, string> ReadClientsTableNames()
    {
        var result = new Dictionary<string, string>();
        var arr = ReadClientsTable();
        foreach (var node in arr)
        {
            if (node is not JsonObject o) continue;
            var id = o["clientId"]?.GetValue<string>();
            var name = o["userData"]?["clientName"]?.GetValue<string>();
            if (id != null && name != null) result[id] = name;
        }
        return result;
    }

    private JsonArray ReadClientsTable()
    {
        var text = ReadContainerFile(ClientsTablePath);
        if (string.IsNullOrWhiteSpace(text)) return new JsonArray();
        try
        {
            return JsonNode.Parse(text) as JsonArray ?? new JsonArray();
        }
        catch (JsonException)
        {
            return new JsonArray();
        }
    }

    /// <summary>Имена устройств в clientsTable — их увидит и официальное приложение AmneziaVPN.</summary>
    private void SyncClientsTable(ServerSnapshot snap)
    {
        var arr = ReadClientsTable();
        var ourKeys = snap.Db.AllDevices.Select(d => d.PublicKey).ToHashSet();
        var active = new Dictionary<string, string>();
        foreach (var u in snap.Db.Users.Where(u => u.Enabled))
            foreach (var d in u.Devices.Where(d => d.Enabled))
                active[d.PublicKey] = $"{u.Name} ({d.Name})";

        var result = new JsonArray();
        var seen = new HashSet<string>();
        foreach (var node in arr)
        {
            if (node is not JsonObject o) continue;
            var id = o["clientId"]?.GetValue<string>() ?? "";
            if (ourKeys.Contains(id))
            {
                if (!active.TryGetValue(id, out var name)) continue; // выключенные и удалённые не показываем
                var userData = o["userData"] as JsonObject ?? new JsonObject();
                userData["clientName"] = name;
                o["userData"] = userData;
                seen.Add(id);
            }
            result.Add(o.DeepClone());
        }
        foreach (var (id, name) in active.Where(kv => !seen.Contains(kv.Key)))
        {
            result.Add(new JsonObject
            {
                ["clientId"] = id,
                ["userData"] = new JsonObject
                {
                    ["clientName"] = name,
                    ["creationDate"] = DateTime.Now.ToString("ddd MMM d HH:mm:ss yyyy", System.Globalization.CultureInfo.InvariantCulture),
                },
            });
        }
        WriteContainerFile(ClientsTablePath, result.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }), "644");
    }

    private void RemoveFromClientsTable(string publicKey)
    {
        var arr = ReadClientsTable();
        var result = new JsonArray();
        foreach (var node in arr)
        {
            if (node is JsonObject o && o["clientId"]?.GetValue<string>() == publicKey) continue;
            if (node != null) result.Add(node.DeepClone());
        }
        WriteContainerFile(ClientsTablePath, result.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }), "644");
    }

    // ───────────────────────────── Работа с контейнером ─────────────────────────────

    private AwgConfigFile ReadConf() =>
        AwgConfigFile.Parse(ReadContainerFile(ConfPath) ?? throw new MayakException($"Не найден {ConfPath}"));

    /// <summary>Записывает awg0.conf и применяет без разрыва соединений (awg syncconf).</summary>
    private void WriteConfAndSync(AwgConfigFile conf)
    {
        WriteContainerFile(ConfPath, conf.ToString(), "600");
        var r = ExecContainer($"awg syncconf awg0 <(awg-quick strip {ConfPath})");
        if (!r.Ok)
        {
            Info("awg syncconf не сработал, перезапускаю контейнер…");
            RestartContainer();
        }
    }

    public CommandResult ExecContainer(string command, TimeSpan? timeout = null, string container = Container) =>
        _ssh.Run($"{S}docker exec {container} bash -c {SshConnection.Q(command)}", timeout);

    private string? ReadContainerFile(string path, string container = Container)
    {
        var r = ExecContainer($"test -f {SshConnection.Q(path)} && cat {SshConnection.Q(path)}", null, container);
        return r.Ok ? r.Output : null;
    }

    private void WriteContainerFile(string path, string content, string mode, string container = Container)
    {
        var tmp = _ssh.UploadTemp(content);
        try
        {
            _ssh.RunChecked($"{S}docker cp {SshConnection.Q(tmp)} {container}:{path}", $"Запись {path}");
        }
        finally
        {
            _ssh.Run($"rm -f {SshConnection.Q(tmp)}");
        }
        ExecContainer($"chown root:root {SshConnection.Q(path)}; chmod {mode} {SshConnection.Q(path)}", null, container);
    }

    private static void ExpectOk(CommandResult r, string what)
    {
        if (r.Output.Contains("MAYAK_OK")) return;
        var err = r.Combined.Split('\n').FirstOrDefault(l => l.Contains("MAYAK_ERROR"))?.Replace("MAYAK_ERROR:", "").Trim();
        throw new MayakException($"{what}: {err ?? "ошибка"}\n{SshConnection.Tail(r.Combined)}");
    }

    public void Dispose() => _ssh.Dispose();
}
