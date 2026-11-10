using Mayak.Api.Provisioning;
using Mayak.Core.Server;

// Изолированный тест (без SSH и сети): установка на занятый сервер через перезапись.
var failed = 0; var passed = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}"); if (ok) passed++; else failed++; }
var plan = new ProvisioningPlan(51820, 8443, false, "fixture");

// 1. Занятый сервер: Supported, Occupied; порт, занятый прежним VPN, не мешает проверке.
var busy = new FakeServer { Occupied = true, PortBusy = true };
var inspection = SshProvisioningBackend.InspectConnected(busy, plan);
Check("занятый сервер (контейнеры, awg0, агент, порт) допускается с отметкой Occupied", inspection is { Supported: true, Occupied: true, Reason: null });

// 2. Порт занят, но VPN нет — по-прежнему отказ (это чужая служба, её не трогаем).
var foreign = new FakeServer { PortBusy = true };
Check("порт, занятый не-VPN службой, по-прежнему останавливает установку", SshProvisioningBackend.InspectConnected(foreign, plan) is { Supported: false, Occupied: false });

// 3. Без подтверждения перезаписи установка не начинается и ничего не удаляется.
var noConsent = new FakeServer { Occupied = true };
var refused = false;
try { await SshProvisioningBackend.PrepareTargetAsync(noConsent, plan, overwrite: false, _ => Task.CompletedTask); }
catch (ProvisioningException) { refused = true; }
Check("без подтверждения перезаписи — отказ, скрипт не запускался", refused && noConsent.OverwriteRuns == 0);

// 4. С подтверждением: шаг overwriting, скрипт под sudo, повторная проверка чистая.
var consent = new FakeServer { Occupied = true, PortBusy = true, Root = false };
var phases = new List<string>();
await SshProvisioningBackend.PrepareTargetAsync(consent, plan, overwrite: true, p => { phases.Add(p); return Task.CompletedTask; });
Check("перезапись: этап overwriting и один запуск скрипта", phases.SequenceEqual(new[] { "overwriting" }) && consent.OverwriteRuns == 1);
Check("скрипт запускается через sudo для не-root и удаляется после", consent.Commands.Any(c => c.StartsWith("sudo -n bash '/tmp/", StringComparison.Ordinal)) && consent.Commands.Any(c => c.StartsWith("rm -f '/tmp/", StringComparison.Ordinal)));
Check("после перезаписи сервер пустой", !consent.Occupied && !consent.PortBusy);

// 5. Пустой сервер — без перезаписи и без этапа overwriting.
var empty = new FakeServer();
phases.Clear();
await SshProvisioningBackend.PrepareTargetAsync(empty, plan, overwrite: true, p => { phases.Add(p); return Task.CompletedTask; });
Check("пустой сервер не перезаписывается даже при overwrite=true", phases.Count == 0 && empty.OverwriteRuns == 0);

// 6. Если после перезаписи что-то осталось — установка останавливается.
var stubborn = new FakeServer { Occupied = true, OverwriteClears = false };
var stopped = false;
try { await SshProvisioningBackend.PrepareTargetAsync(stubborn, plan, overwrite: true, _ => Task.CompletedTask); }
catch (ProvisioningException) { stopped = true; }
Check("остатки после перезаписи останавливают установку", stopped && stubborn.OverwriteRuns == 1);

// 7. Скрипт: архив до удаления, права 077, нет вывода значений.
var script = SshProvisioningBackend.OverwriteScript;
Check("скрипт: umask 077 и архив до удаления", script.Contains("umask 077") && script.IndexOf("tar czf", StringComparison.Ordinal) < script.IndexOf("rm -rf", StringComparison.Ordinal)
    && script.IndexOf("tar czf", StringComparison.Ordinal) < script.IndexOf("rm -f", StringComparison.Ordinal));
Check("скрипт не печатает содержимое (только метки STEP_)", !script.Contains("cat ") && script.Split('\n').Where(l => l.Contains("echo")).All(l => l.Contains("echo STEP_")));

// 8. Пинг с машины API: правило ACCEPT только для её IPv4, вставляется первым, под sudo; мусор не принимается.
var icmp = new FakeServer { Root = false };
SshProvisioningBackend.AllowProbeIcmp(icmp, "5.42.104.30");
var cmd = icmp.Commands.Single();
Check("пинг: правило для одного адреса /32, вставка первой строкой, под sudo",
    cmd.Contains("sudo -n iptables -C INPUT -p icmp --icmp-type echo-request -s 5.42.104.30/32 -j ACCEPT") &&
    cmd.Contains("|| sudo -n iptables -I INPUT 1 -p icmp --icmp-type echo-request -s 5.42.104.30/32 -j ACCEPT"));
var junk = new FakeServer();
SshProvisioningBackend.AllowProbeIcmp(junk, "5.42.104.30; rm -rf /");
SshProvisioningBackend.AllowProbeIcmp(junk, "::1");
SshProvisioningBackend.AllowProbeIcmp(junk, null);
Check("пинг: недопустимый адрес, IPv6 и пусто — без команд", junk.Commands.Count == 0);
Check("адрес API берётся из IP в PublicUrl", SshProvisioningBackend.ResolveProbeSource("https://5.42.104.30") == "5.42.104.30"
    && SshProvisioningBackend.ResolveProbeSource("http://127.0.0.1:5080") == null);

Console.WriteLine($"passed={passed} failed={failed}");
return failed == 0 ? 0 : 1;

sealed class FakeServer : IShell
{
    public bool Occupied { get; set; }
    public bool PortBusy { get; set; }
    public bool Root { get; init; } = true;
    public bool OverwriteClears { get; init; } = true;
    public int OverwriteRuns { get; private set; }
    public List<string> Commands { get; } = new();
    public string Sudo => Root ? "" : "sudo -n ";
    public bool IsRoot => Root;
    public string? ServerFingerprint => null;
    public string? JumpFingerprint => null;
    public void Connect() { }
    public bool IsAlive() => true;
    public void Dispose() { }
    public string UploadTemp(string content, string suffix = "") => "/tmp/mayak-fixture" + suffix;
    public void WriteHostFile(string content, string remotePath, string mode = "644") => throw new NotSupportedException();
    public string RunChecked(string command, string what, TimeSpan? timeout = null) => throw new NotSupportedException();
    public CommandResult RunScript(string script, TimeSpan timeout) => throw new NotSupportedException();
    public CommandResult Run(string command, TimeSpan? timeout = null)
    {
        Commands.Add(command);
        if (command == "cat /etc/os-release") return new(0, "ID=ubuntu\nVERSION_ID=\"24.04\"", "");
        if (command == "uname -m") return new(0, "x86_64", "");
        if (command == "sudo -n true") return new(0, "", "");
        if (command.Contains("ss -H -lntu")) return new(0, PortBusy ? "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*" : "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", "");
        if (command.Contains("for r in docker podman")) return new(0, Occupied ? "__PRESENT_docker__\nabc123\n__ABSENT_podman__" : "__PRESENT_docker__\n__ABSENT_podman__", "");
        if (command.Contains("/etc/mayak/agent.json")) return new(0, Occupied ? "MAYAK_EXISTING_ARTIFACT" : "", "");
        if (command.Contains("systemctl list-units")) return new(0, Occupied ? "mayak-agent.service loaded active running Mayak agent" : "ssh.service loaded active running OpenSSH", "");
        if (command == "ip -o link show") return new(0, "1: lo: <LOOPBACK> mtu 65536\n2: eth0: <BROADCAST> mtu 1500" + (Occupied ? "\n3: awg0: <POINTOPOINT> mtu 1420" : ""), "");
        if (command.Contains("command -v wg")) return new(0, "__NO_WG_TOOL__", "");
        if (command.Contains("bash '/tmp/mayak-fixture.sh'"))
        {
            OverwriteRuns++;
            if (OverwriteClears) { Occupied = false; PortBusy = false; }
            return new(0, "STEP_ARCHIVED\nSTEP_CONTAINERS\nSTEP_SERVICES\nSTEP_DONE\n", "");
        }
        if (command.StartsWith("rm -f '/tmp/")) return new(0, "", "");
        if (command.Contains("iptables -C INPUT -p icmp")) return new(0, "", "");
        throw new InvalidOperationException("Unexpected command: " + command);
    }
}
