using Mayak.Core.Crypto;
using Mayak.Core.Models;
using Mayak.Core.Xray;

namespace Mayak.Core.Server;

/// <summary>Итог самопроверки Xray на самом сервере.</summary>
public sealed record XraySelfTestResult(bool Ok, string Details);

public sealed class XrayInstallOptions
{
    public int Port { get; set; } = XrayDefaults.DefaultPort;
    /// <summary>Сайт, под который маскируется Reality.</summary>
    public string Sni { get; set; } = XrayDefaults.DefaultSni;
}

/// <summary>Xray (VLESS + Reality + XHTTP) и служебная учётка для проверки протоколов.</summary>
public sealed partial class MayakServer
{
    public const string XrayContainer = "amnezia-xray";
    public const string XrayDir = "/opt/amnezia/xray";
    public const string XrayServerJson = XrayDir + "/server.json";
    public const string XrayDockerfileFolder = "/opt/amnezia/amnezia-xray";

    public ServerState GetXrayState()
    {
        var state = _ssh.Run($"{S}docker inspect -f '{{{{.State.Status}}}}' {XrayContainer} 2>/dev/null").Output.Trim();
        return state switch
        {
            "" => ServerState.DockerOnly,
            "running" => ServerState.Running,
            _ => ServerState.Stopped,
        };
    }

    private void LoadXray(ServerSnapshot snap)
    {
        snap.XrayState = GetXrayState();
        snap.Xray = null;
        if (snap.XrayState != ServerState.Running) return;
        var json = ReadContainerFile(XrayServerJson, XrayContainer);
        var pub = ReadContainerFile(XrayDir + "/xray_public.key", XrayContainer)?.Trim();
        if (string.IsNullOrWhiteSpace(json) || string.IsNullOrEmpty(pub))
        {
            snap.Warnings.Add("Контейнер Xray есть, но не настроен. Переустановите Xray на вкладке «Сервер».");
            return;
        }
        try
        {
            snap.Xray = XrayConfig.ParseServerJson(json, pub);
        }
        catch (Exception ex)
        {
            snap.Warnings.Add("Не удалось прочитать настройки Xray: " + ex.Message);
        }
    }

    /// <summary>
    /// Закрытые ключи сервера (AmneziaWG и Reality): нужны API, чтобы ставить другие выходы клонами этого.
    /// Вызывается только агентом на самом сервере.
    /// </summary>
    public (string AwgPrivateKey, string? XrayPrivateKey) ReadServerSecrets()
    {
        var conf = ReadConf();
        var awg = conf.GetInterfaceValue("PrivateKey") ?? throw new MayakException("В awg0.conf нет PrivateKey.");
        string? xray = null;
        if (GetXrayState() == ServerState.Running)
        {
            var json = ReadContainerFile(XrayServerJson, XrayContainer);
            if (!string.IsNullOrWhiteSpace(json)) xray = XrayConfig.ReadRealityPrivateKey(json);
        }
        return (awg, xray);
    }

    /// <summary>Устанавливает Xray рядом с AmneziaWG и выдаёт его всем активным устройствам.</summary>
    public void InstallXray(ServerSnapshot snap, XrayInstallOptions opt, bool reinstall, Action<string>? step = null)
    {
        void Step(string s) { step?.Invoke(s); Info("▸ " + s); }

        var state = GetXrayState();
        if (state is ServerState.Running or ServerState.Stopped)
        {
            if (!reinstall)
                throw new MayakException("Xray уже установлен. Выберите переустановку, если нужно начать заново.");
            Step("Удаление старого контейнера Xray");
            _ssh.Run($"{S}docker stop {XrayContainer}; {S}docker rm -fv {XrayContainer}; {S}docker rmi {XrayContainer}; {S}docker volume rm {XrayContainer}-data", TimeSpan.FromMinutes(3));
        }

        var busy = _ssh.Run($"({S}ss -ltn 2>/dev/null || {S}netstat -ltn 2>/dev/null) | grep -E '[:.]{opt.Port}\\s' >/dev/null && echo busy || echo free").Output.Trim();
        if (busy == "busy")
            throw new MayakException($"TCP-порт {opt.Port} занят (возможно, веб-сервер). Выберите другой порт для Xray.");

        Step("Подготовка сервера");
        var vars = new Dictionary<string, string> { ["SUDO"] = S.Trim(), ["DOCKERFILE_FOLDER"] = XrayDockerfileFolder };
        ExpectOk(_ssh.RunScript(ScriptLibrary.Load("prepare_host.sh", vars), TimeSpan.FromMinutes(3)), "Подготовка сервера");

        Step("Сборка контейнера Xray (2–5 минут)");
        var dockerfile = ScriptLibrary.Load("xray.Dockerfile", new Dictionary<string, string>
        {
            ["XRAY_RELEASE"] = XrayDefaults.Release,
            ["XRAY_SHA256"] = XrayDefaults.LinuxZipSha256,
        });
        _ssh.WriteHostFile(dockerfile, XrayDockerfileFolder + "/Dockerfile");
        var build = _ssh.Run($"{S}docker build --no-cache --pull -t {XrayContainer} {XrayDockerfileFolder} 2>&1", TimeSpan.FromMinutes(25));
        if (!build.Ok)
            throw new MayakException("Не удалось собрать контейнер Xray (Docker Hub или GitHub недоступны с сервера?).\n" + SshConnection.Tail(build.Combined));

        Step("Запуск контейнера Xray");
        _ssh.RunChecked(
            $"{S}docker run -d --privileged --log-driver none --restart always --cap-add=NET_ADMIN " +
            $"-p {opt.Port}:{opt.Port}/tcp -p {opt.Port}:{opt.Port}/udp " +
            $"-v {XrayContainer}-data:{XrayDir} --name {XrayContainer} {XrayContainer}", "Запуск контейнера Xray");
        _ssh.Run($"{S}docker network connect amnezia-dns-net {XrayContainer}");
        ExecContainer("mkdir -p /dev/net; if [ ! -c /dev/net/tun ]; then mknod /dev/net/tun c 10 200; fi", null, XrayContainer);

        Step("Ключи Reality");
        WriteContainerFile("/opt/amnezia/xray_configure.sh", ScriptLibrary.Load("xray_configure.sh"), "755", XrayContainer);
        var conf = ExecContainer("bash /opt/amnezia/xray_configure.sh", TimeSpan.FromMinutes(1), XrayContainer);
        if (conf.Output.Contains("keygen=failed"))
            throw new MayakException("Xray не смог создать ключи Reality:\n" + SshConnection.Tail(conf.Combined));

        var priv = ReadContainerFile(XrayDir + "/xray_private.key", XrayContainer)?.Trim();
        var pub = ReadContainerFile(XrayDir + "/xray_public.key", XrayContainer)?.Trim();
        var sid = ReadContainerFile(XrayDir + "/xray_short_id.key", XrayContainer)?.Trim();
        var owner = ReadContainerFile(XrayDir + "/xray_uuid.key", XrayContainer)?.Trim();
        if (string.IsNullOrEmpty(priv) || string.IsNullOrEmpty(pub) || string.IsNullOrEmpty(sid))
            throw new MayakException("Ключи Reality не созданы.");

        var ep = new XrayEndpoint
        {
            Port = opt.Port,
            PublicKey = pub,
            ShortId = sid,
            Sni = opt.Sni.Trim(),
            Transport = "xhttp",
            XhttpPath = XrayConfig.RandomPath(),
            XhttpHost = opt.Sni.Trim(),
            XhttpMode = "auto",
        };
        snap.Xray = ep;
        EnsureXrayIds(snap.Db);

        var clients = DesiredXrayClients(snap).ToList();
        if (!string.IsNullOrEmpty(owner))
            clients.Insert(0, new XrayConfig.Client(owner, "", "")); // учётка владельца, как у AmneziaVPN

        Step("Настройка и проверка конфигурации");
        WriteContainerFile(StartScriptPath, ScriptLibrary.Load("xray_start.sh", new Dictionary<string, string> { ["XRAY_PORT"] = opt.Port.ToString() }), "755", XrayContainer);
        ApplyXrayServerJson(XrayConfig.BuildServerJson(ep, priv, clients));

        WriteDatabaseFile(snap.Db);
        snap.XrayState = ServerState.Running;
        Info($"Xray установлен: {ep.Title}, TCP-порт {opt.Port}, маскировка под {ep.Sni}. Выдайте устройствам файлы заново, чтобы у них появился второй протокол.");
    }

    public void UninstallXray(ServerSnapshot snap)
    {
        _ssh.Run($"{S}docker stop {XrayContainer}; {S}docker rm -fv {XrayContainer}; {S}docker rmi {XrayContainer}; {S}docker volume rm {XrayContainer}-data; {S}rm -rf {XrayDockerfileFolder}", TimeSpan.FromMinutes(3));
        snap.Xray = null;
        snap.XrayState = ServerState.DockerOnly;
        Info("Xray удалён с сервера.");
    }

    /// <summary>У каждого устройства и у проверочной учётки должен быть свой UUID Xray.</summary>
    private static void EnsureXrayIds(MayakDatabase db)
    {
        foreach (var d in db.AllDevices.Where(d => string.IsNullOrEmpty(d.XrayId)))
            d.XrayId = Guid.NewGuid().ToString();
        if (db.Probe != null && string.IsNullOrEmpty(db.Probe.XrayId))
            db.Probe.XrayId = Guid.NewGuid().ToString();
    }

    private static IEnumerable<XrayConfig.Client> DesiredXrayClients(ServerSnapshot snap)
    {
        var flow = snap.Xray?.Transport == "raw" ? snap.Xray.Flow : "";
        foreach (var u in snap.Db.Users.Where(u => u.Enabled))
            foreach (var d in u.Devices.Where(d => d.Enabled && !string.IsNullOrEmpty(d.XrayId)))
                yield return new XrayConfig.Client(d.XrayId, XrayConfig.MayakEmailPrefix + d.Id.ToString("N"), flow);
        if (snap.Db.Probe is { XrayId.Length: > 0 } probe)
            yield return new XrayConfig.Client(probe.XrayId, XrayConfig.ProbeEmail, flow);
    }

    /// <summary>
    /// Приводит список клиентов в server.json к базе: свои (email «mayak:…») — по активным устройствам,
    /// чужие (выданные из AmneziaVPN) остаются как есть.
    /// </summary>
    private void SyncXrayClients(ServerSnapshot snap)
    {
        var json = ReadContainerFile(XrayServerJson, XrayContainer);
        if (string.IsNullOrWhiteSpace(json)) return;
        var current = XrayConfig.ReadClients(json);
        var foreign = current.Where(c => !c.Email.StartsWith(XrayConfig.MayakEmailPrefix, StringComparison.Ordinal));
        var desired = foreign.Concat(DesiredXrayClients(snap)).ToList();

        var a = string.Join("|", current.Select(c => c.Id + "/" + c.Flow).OrderBy(x => x));
        var b = string.Join("|", desired.Select(c => c.Id + "/" + c.Flow).OrderBy(x => x));
        if (a == b) return;

        ApplyXrayServerJson(XrayConfig.ReplaceClients(json, desired));
        Info("Список клиентов Xray обновлён.");
    }

    /// <summary>Как у AmneziaVPN: новый конфиг проверяется «xray -test», затем подменяется и контейнер перезапускается.</summary>
    private void ApplyXrayServerJson(string json)
    {
        const string staged = XrayDir + "/server.new.json";
        WriteContainerFile(staged, json, "600", XrayContainer);
        var test = ExecContainer($"xray -test -format json -config {staged} 2>&1 || xray -test -config {staged} 2>&1", TimeSpan.FromMinutes(1), XrayContainer);
        if (!test.Ok)
        {
            ExecContainer($"rm -f {staged}", null, XrayContainer);
            throw new MayakException("Xray отклонил конфигурацию, сервер не изменён:\n" + SshConnection.Tail(test.Combined));
        }
        ExecContainer($"[ -f {XrayServerJson} ] && cp {XrayServerJson} {XrayServerJson}.bak; mv {staged} {XrayServerJson}", null, XrayContainer);
        _ssh.RunChecked($"{S}docker restart {XrayContainer}", "Перезапуск Xray");

        for (int i = 0; i < 8; i++)
        {
            Thread.Sleep(1000);
            if (ExecContainer("pgrep xray >/dev/null 2>&1", null, XrayContainer).Ok) return;
        }
        // откат
        ExecContainer($"[ -f {XrayServerJson}.bak ] && cp {XrayServerJson}.bak {XrayServerJson}", null, XrayContainer);
        _ssh.Run($"{S}docker restart {XrayContainer}");
        throw new MayakException("Xray не запустился с новой конфигурацией, возвращена прежняя.");
    }

    // ───────────── Проверка протоколов ─────────────

    /// <summary>Создаёт (если нужно) служебную учётку для проверки: пир AmneziaWG и клиент Xray.</summary>
    public ProbeIdentity EnsureProbe(ServerSnapshot snap)
    {
        var db = snap.Db;
        bool changed = false;
        if (db.Probe == null || string.IsNullOrEmpty(db.Probe.AwgPrivateKey))
        {
            var (priv, pub) = Curve25519.GenerateKeyPair();
            var conf0 = ReadConf();
            var used = conf0.Peers.Select(p => p.Ip ?? "").Concat(db.AllDevices.Select(d => d.Ip));
            db.Probe = new ProbeIdentity
            {
                AwgPrivateKey = priv,
                AwgPublicKey = pub,
                AwgIp = IpAllocator.Next(snap.Endpoint.SubnetAddress, int.Parse(snap.Endpoint.SubnetCidr), snap.ServerAddress, used),
                XrayId = db.Probe?.XrayId ?? "",
            };
            changed = true;
        }

        var conf = ReadConf();
        if (!conf.HasPeer(db.Probe.AwgPublicKey))
        {
            conf.AddPeer(db.Probe.AwgPublicKey, snap.Endpoint.PresharedKey, db.Probe.AwgIp);
            WriteConfAndSync(conf);
            snap.PeersOnServer.Add(db.Probe.AwgPublicKey);
            Info("Создано служебное подключение для проверки протоколов.");
        }

        if (snap.Xray != null && string.IsNullOrEmpty(db.Probe.XrayId))
        {
            db.Probe.XrayId = Guid.NewGuid().ToString();
            changed = true;
        }
        if (changed) WriteDatabaseFile(db);
        if (snap.Xray != null) SyncXrayClients(snap);
        return db.Probe;
    }

    /// <summary>
    /// Запускает xray-клиент внутри контейнера, подключается им к серверу на 127.0.0.1 (минуя сеть)
    /// и выходит через него в интернет. Отвечает на вопрос «конфигурация рабочая?» независимо от блокировок.
    /// </summary>
    public XraySelfTestResult SelfTestXray(ServerSnapshot snap, ProbeIdentity probe)
    {
        if (snap.Xray == null || string.IsNullOrEmpty(probe.XrayId))
            return new XraySelfTestResult(false, "Xray не установлен.");
        const string cfg = "/tmp/mayak_selftest.json";
        WriteContainerFile(cfg, XrayConfig.BuildClientJson("127.0.0.1", snap.Xray, probe.XrayId, 10899), "600", XrayContainer);
        var script =
            $"xray run -c {cfg} >/tmp/mayak_selftest.log 2>&1 & P=$!; sleep 2; " +
            "C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 -x socks5h://127.0.0.1:10899 https://www.google.com/generate_204); " +
            $"kill $P 2>/dev/null; echo MAYAK_SELFTEST=$C; tail -n 4 /tmp/mayak_selftest.log; rm -f {cfg}";
        var r = ExecContainer(script, TimeSpan.FromSeconds(45), XrayContainer);
        var line = r.Output.Split('\n').FirstOrDefault(l => l.StartsWith("MAYAK_SELFTEST=")) ?? "";
        var code = line.Replace("MAYAK_SELFTEST=", "").Trim();
        bool ok = code is "204" or "200";
        var log = string.Join(" ", r.Output.Split('\n').Where(l => !l.StartsWith("MAYAK_SELFTEST=") && l.Trim().Length > 0)).Trim();
        return new XraySelfTestResult(ok, ok
            ? "Самопроверка на сервере: Xray принимает подключение и выпускает в интернет — конфигурация рабочая."
            : $"Самопроверка на сервере не прошла (код {(code.Length == 0 ? "нет ответа" : code)}). {log}".Trim());
    }

    /// <summary>IP-адрес, с которого Маяк подключился к серверу (как его видит сервер).</summary>
    public string GetClientAddress()
    {
        // Через промежуточный сервер SSH видит его адрес, а не адрес пользователя.
        if (_creds.Jump != null) return "";
        var r = _ssh.Run("echo $SSH_CONNECTION").Output.Trim();
        return r.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
    }
}
