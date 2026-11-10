using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Microsoft.EntityFrameworkCore;

[assembly: InternalsVisibleTo("Mayak.ApiTest")]
[assembly: InternalsVisibleTo("Mayak.ProvisioningOverwriteTest")]

namespace Mayak.Api.Provisioning;

public sealed class ProvisioningCredentials
{
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string User { get; init; } = "";
    public string Password { get; set; } = "";
    public string TrustedFingerprint { get; init; } = "";
    public ProvisioningCredentials() { }
    public ProvisioningCredentials(string host, int port, string user, string password, string trustedFingerprint)
    { Host = host; Port = port; User = user; Password = password; TrustedFingerprint = trustedFingerprint; }
}
public sealed record ProvisioningPlan(int AwgPort, int XrayPort, bool BootstrapIdentity, string IdentityVersionHash);
/// <param name="Occupied">
/// На сервере уже есть контейнеры, VPN, интерфейсы WireGuard/AmneziaWG или агент. Установка возможна только с перезаписью:
/// прежнее сохраняется в архив на сервере и удаляется (<see cref="SshProvisioningBackend.OverwriteScript"/>).
/// </param>
public sealed record ProvisioningInspection(bool Supported, string? Reason, string OperatingSystem, string OsVersion, string Architecture, bool RootOrSudo, int AwgPort, int XrayPort, bool BootstrapIdentity, bool Occupied = false);

public static class ProvisioningRules
{
    private static readonly (uint Start, uint End)[] NonPublicRanges =
    {
        (0x00000000, 0x00ffffff), // this network
        (0x0a000000, 0x0affffff), // private
        (0x64400000, 0x647fffff), // carrier-grade NAT
        (0x7f000000, 0x7fffffff), // loopback
        (0xa9fe0000, 0xa9feffff), // link-local / cloud metadata
        (0xac100000, 0xac1fffff), // private
        (0xc0000000, 0xc00000ff), // IETF special use
        (0xc0000200, 0xc00002ff), // documentation
        (0xc0586300, 0xc05863ff), // deprecated relay anycast
        (0xc0a80000, 0xc0a8ffff), // private
        (0xc6120000, 0xc613ffff), // benchmarking
        (0xc6336400, 0xc63364ff), // documentation
        (0xcb007100, 0xcb0071ff), // documentation
        (0xe0000000, 0xffffffff), // multicast, reserved, broadcast
    };

    public static bool TryPublicIpv4(string? value, string? apiUrl, out string address, out string error)
    {
        address = "";
        error = "Укажите публичный IPv4 адрес сервера.";
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim() || value.Contains('%') ||
            !IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != value)
            return false;
        var bytes = ip.GetAddressBytes();
        uint n = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        if (NonPublicRanges.Any(r => n >= r.Start && n <= r.End) || value == "5.42.104.30")
        {
            error = "Этот адрес является внутренним, зарезервированным или относится к API/Москве.";
            return false;
        }
        if (Uri.TryCreate(apiUrl, UriKind.Absolute, out var api) && IPAddress.TryParse(api.Host, out var apiIp) && apiIp.Equals(ip))
        {
            error = "Нельзя устанавливать VPN на адрес самого API.";
            return false;
        }
        address = ip.ToString();
        error = "";
        return true;
    }

    public static bool ValidSshPort(int port) => port is >= 1 and <= 65535;
    public static bool ValidUser(string? user) => !string.IsNullOrWhiteSpace(user) && user.Length <= 32 && Regex.IsMatch(user, "^[a-z_][a-z0-9_-]*$", RegexOptions.CultureInvariant);
    public static bool ValidFingerprint(string? fingerprint) => fingerprint != null && Regex.IsMatch(fingerprint, "^SHA256:[A-Za-z0-9+/]{43}$", RegexOptions.CultureInvariant);

    public static bool IsOccupied(string ssOutput, int port, bool tcp)
    {
        return TryParseSocketTable(ssOutput, out var rows) && rows.Any(row => row.Tcp == tcp && row.Port == port);
    }

    public static bool ValidSocketTable(string ssOutput)
    {
        return TryParseSocketTable(ssOutput, out _);
    }

    private readonly record struct SocketRow(bool Tcp, int Port);

    private static bool TryParseSocketTable(string ssOutput, out List<SocketRow> rows)
    {
        rows = new List<SocketRow>();
        foreach (var line in ssOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 6) return false;
            bool tcp = fields[0] is "tcp" or "tcp6";
            bool udp = fields[0] is "udp" or "udp6";
            bool ipv6 = fields[0] is "tcp6" or "udp6";
            if (!tcp && !udp) return false;
            if ((tcp && fields[1] != "LISTEN") || (udp && fields[1] != "UNCONN")) return false;
            if (!long.TryParse(fields[2], out var recvQ) || recvQ < 0 ||
                !long.TryParse(fields[3], out var sendQ) || sendQ < 0 ||
                !TrySocketEndpoint(fields[5], allowWildcardPort: true, ipv6, out _) ||
                !TrySocketEndpoint(fields[4], allowWildcardPort: false, ipv6, out var port)) return false;
            rows.Add(new SocketRow(tcp, port));
        }
        return true;
    }

    private static bool TrySocketEndpoint(string endpoint, bool allowWildcardPort, bool ipv6, out int port)
    {
        port = 0;
        if (endpoint.Length == 0) return false;
        int colon = endpoint.LastIndexOf(':');
        if (colon <= 0 || colon == endpoint.Length - 1) return false;
        string address = endpoint[..colon];
        string portText = endpoint[(colon + 1)..];
        bool wildcardPort = portText == "*";
        if (wildcardPort)
        {
            if (!allowWildcardPort) return false;
        }
        else if (!int.TryParse(portText, out port) || port is < 0 or > 65535) return false;
        if (address == "*") return true;
        bool bracketed = address.StartsWith('[');
        if (bracketed)
        {
            if (!address.Contains(']')) return false;
            int close = address.IndexOf(']');
            bool hasOutsideZone = close != address.Length - 1;
            bool hasInsideZone = address.AsSpan(1, close - 1).Contains('%');
            if (hasOutsideZone && hasInsideZone) return false;
            if (hasOutsideZone)
            {
                if (address[close + 1] != '%' || close + 2 == address.Length) return false;
                string bracketZone = address[(close + 2)..];
                if (!Regex.IsMatch(bracketZone, @"^[A-Za-z0-9_.-]+$")) return false;
            }
            address = address[1..close];
        }
        else if (address.Contains(']') || address.Contains('[')) return false;
        int zone = address.IndexOf('%');
        if (zone >= 0)
        {
            if (zone == address.Length - 1 || !Regex.IsMatch(address[(zone + 1)..], @"^[A-Za-z0-9_.-]+$")) return false;
            address = address[..zone];
        }
        return IPAddress.TryParse(address, out var ip) &&
            (!ipv6 || ip.AddressFamily == AddressFamily.InterNetworkV6) &&
            (!bracketed || ip.AddressFamily == AddressFamily.InterNetworkV6);
    }

    public static bool ValidInterfaceTable(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .All(line => Regex.IsMatch(line, @"^\d+:\s*[^:]+:\s*<[^>]*>")) &&
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length > 0;
}

public interface IProvisioningBackend
{
    Task<string> ReadHostFingerprintAsync(string host, int port, CancellationToken ct);
    Task<ProvisioningInspection> InspectAsync(ProvisioningCredentials credentials, ProvisioningPlan plan, CancellationToken ct);
    Task InstallAsync(ProvisioningInstallContext context, Func<string, Task> progress, CancellationToken ct);
}

public sealed record ProvisioningInstallContext(
    Guid ServerId,
    string Name,
    ProvisioningCredentials Credentials,
    ProvisioningPlan Plan,
    ClusterIdentity? ClusterIdentity,
    string AgentToken,
    string PublicUrl,
    bool Overwrite = false);

/// <summary>Read-only target validation and isolated installation of a new, explicitly trusted node.</summary>
public sealed class SshProvisioningBackend : IProvisioningBackend
{
    public Task<string> ReadHostFingerprintAsync(string host, int port, CancellationToken ct) =>
        Task.Run(() => SshConnection.ReadHostKeyFingerprint(host, port), ct);

    public Task<ProvisioningInspection> InspectAsync(ProvisioningCredentials credentials, ProvisioningPlan plan, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.Run(() =>
        {
            using var ssh = NewShell(credentials);
            using var cancellation = ct.Register(ssh.Cancel);
            ssh.Connect();
            if (!string.Equals(ssh.ServerFingerprint, credentials.TrustedFingerprint, StringComparison.Ordinal))
                throw new ProvisioningException("SSH fingerprint changed");
            return InspectConnected(ssh, plan);
        }, ct);
    }

    public async Task InstallAsync(ProvisioningInstallContext context, Func<string, Task> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var cred = context.Credentials;
        var api = ValidateAgentApi(context.PublicUrl);
        using var ssh = NewShell(cred);
        using var cancellation = ct.Register(ssh.Cancel);
        using var vpn = new MayakServer(ssh, cred.Host);
        vpn.Connect();
        if (!string.Equals(vpn.Fingerprint, cred.TrustedFingerprint, StringComparison.Ordinal))
            throw new ProvisioningException("SSH fingerprint changed");

        var plan = context.Plan;
        var cloned = context.ClusterIdentity != null;
        if (cloned)
        {
            var awg = ClusterService.AwgOf(context.ClusterIdentity!);
            var xray = ClusterService.XrayOf(context.ClusterIdentity!);
            if (xray == null || string.IsNullOrWhiteSpace(context.ClusterIdentity!.XrayPrivateKey))
                throw new ProvisioningException("Cluster Xray identity is not available for a safe clone");
            await PrepareTargetAsync(ssh, plan, context.Overwrite, progress);
            await progress("installing_awg");
            vpn.Install(new InstallOptions
            {
                Port = awg.Port,
                Title = context.ClusterIdentity.Title,
                Dns1 = context.ClusterIdentity.Dns1,
                Dns2 = context.ClusterIdentity.Dns2,
                SharedIdentity = awg,
                SharedServerPrivateKey = context.ClusterIdentity.AwgServerPrivateKey,
            }, reinstall: false, _ => { });
            await progress("installing_xray");
            vpn.InstallXray(vpn.Load(), new XrayInstallOptions { SharedIdentity = xray, SharedPrivateKey = context.ClusterIdentity.XrayPrivateKey }, reinstall: false, _ => { });

            var loaded = vpn.Load();
            var secrets = vpn.ReadServerSecrets();
            if (!IdentityMatches(loaded.Endpoint, secrets.AwgPrivateKey, awg, context.ClusterIdentity.AwgServerPrivateKey) ||
                loaded.Xray == null || !XrayMatches(loaded.Xray, xray) || secrets.XrayPrivateKey != context.ClusterIdentity.XrayPrivateKey)
                throw new ProvisioningException("Installed server identity does not match cluster");
        }
        else
        {
            await PrepareTargetAsync(ssh, plan, context.Overwrite, progress);
            await progress("installing_awg");
            vpn.Install(new InstallOptions { Port = plan.AwgPort, InstallXray = true }, reinstall: false, _ => { });
            await progress("installing_xray");
            vpn.InstallXray(vpn.Load(), new XrayInstallOptions { Port = plan.XrayPort }, reinstall: false, _ => { });
            var loaded = vpn.Load();
            if (loaded.Xray == null || loaded.Endpoint.Port != plan.AwgPort || loaded.Xray.Port != plan.XrayPort)
                throw new ProvisioningException("New cluster identity failed local runtime verification");
        }

        await InstallAgentAsync(ssh, context, api, progress, ct);
    }

    internal static string ValidateAgentApi(string publicUrl)
    {
        var api = publicUrl.TrimEnd('/');
        var apiUri = new Uri(api, UriKind.Absolute);
        if (apiUri.Scheme != Uri.UriSchemeHttps && !IPAddress.IsLoopback(IPAddress.TryParse(apiUri.Host, out var apiIp) ? apiIp : IPAddress.None))
            throw new ProvisioningException("The configured agent API URL must use HTTPS");
        return api;
    }

    internal static async Task InstallAgentAsync(IShell ssh, ProvisioningInstallContext context, string api,
        Func<string, Task> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await progress("installing_agent");
        var binaryUrl = new Uri(new Uri(api + "/"), "download/mayak-agent").ToString();
        var json = JsonSerializer.Serialize(new { api, token = context.AgentToken });
        ssh.RunChecked($"{ssh.Sudo}mkdir -p /opt/mayak /etc/mayak /var/lib/mayak-agent", "Подготовка агента");
        ssh.WriteHostFile(json + "\n", "/etc/mayak/agent.json", "600");
        ssh.RunChecked($"{ssh.Sudo}curl -fsSL --retry 3 --max-time 120 {SshConnection.Q(binaryUrl)} -o /opt/mayak/mayak-agent.new && {ssh.Sudo}chmod 755 /opt/mayak/mayak-agent.new && {ssh.Sudo}mv /opt/mayak/mayak-agent.new /opt/mayak/mayak-agent",
            "Загрузка агента", TimeSpan.FromMinutes(3));
        var unit = "[Unit]\nDescription=Mayak agent\nAfter=network-online.target docker.service\nWants=network-online.target\n\n" +
                   "[Service]\nExecStart=/opt/mayak/mayak-agent /etc/mayak/agent.json\nRestart=always\nRestartSec=10\nStateDirectory=mayak-agent\nEnvironment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/mayak-agent\n\n" +
                   "[Install]\nWantedBy=multi-user.target\n";
        ssh.WriteHostFile(unit, "/etc/systemd/system/mayak-agent.service", "644");
        ct.ThrowIfCancellationRequested();
        await progress("awaiting_agent");
        ssh.RunChecked($"{ssh.Sudo}systemctl daemon-reload && {ssh.Sudo}systemctl enable -q mayak-agent && {ssh.Sudo}systemctl restart mayak-agent", "Запуск агента", TimeSpan.FromMinutes(2));
    }

    private static SshConnection NewShell(ProvisioningCredentials c) => new(new SshCredentials
    {
        Host = c.Host, Port = c.Port, User = c.User, Password = c.Password,
        KnownHostFingerprint = c.TrustedFingerprint,
    }, cleanupStaleFiles: false, sftpOperationTimeout: TimeSpan.FromSeconds(45));

    internal static ProvisioningInspection InspectConnected(IShell shell, ProvisioningPlan plan)
    {
        string osText, arch, sockets;
        bool rootOrSudo, hasContainers, hasArtifacts, hasVpnService, hasVpnInterface, hasWireGuardConfig;
        string os = "unknown", version = "unknown";
        try
        {
            osText = RunProbe(shell, "cat /etc/os-release", TimeSpan.FromSeconds(10)).Output;
            arch = RunProbe(shell, "uname -m", TimeSpan.FromSeconds(10)).Output.Trim();
            if (string.IsNullOrWhiteSpace(osText) || string.IsNullOrWhiteSpace(arch)) throw new ProvisioningException("Missing OS probe output");
            var values = osText.Split('\n').Select(line => line.Split('=', 2)).Where(x => x.Length == 2)
                .ToDictionary(x => x[0].Trim(), x => x[1].Trim().Trim('"'), StringComparer.Ordinal);
            os = values.GetValueOrDefault("ID", "unknown");
            version = values.GetValueOrDefault("VERSION_ID", "unknown");
            rootOrSudo = shell.IsRoot || shell.Run("sudo -n true", TimeSpan.FromSeconds(10)).Ok;
            if (!rootOrSudo) return new ProvisioningInspection(false, "Нужен root или sudo без пароля.", os, version, arch, false, plan.AwgPort, plan.XrayPort, plan.BootstrapIdentity);

            sockets = RunProbe(shell, shell.Sudo + "ss -H -lntu", TimeSpan.FromSeconds(10)).Output;
            if (!ProvisioningRules.ValidSocketTable(sockets)) throw new ProvisioningException("Ambiguous socket table");

            var containerProbe = RunProbe(shell, shell.Sudo + "sh -c 'for r in docker podman; do if command -v \"$r\" >/dev/null 2>&1; then echo __PRESENT_${r}__; \"$r\" ps -aq || exit 51; else echo __ABSENT_${r}__; fi; done'", TimeSpan.FromSeconds(15)).Output;
            var containerLines = containerProbe.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool dockerKnown = containerLines.Contains("__PRESENT_docker__") || containerLines.Contains("__ABSENT_docker__");
            bool podmanKnown = containerLines.Contains("__PRESENT_podman__") || containerLines.Contains("__ABSENT_podman__");
            if (!dockerKnown || !podmanKnown) throw new ProvisioningException("Ambiguous container probe");
            hasContainers = containerLines.Any(line => line is not ("__PRESENT_docker__" or "__ABSENT_docker__" or "__PRESENT_podman__" or "__ABSENT_podman__"));

            var artifacts = RunProbe(shell, shell.Sudo + "sh -c 'for p in /etc/mayak/agent.json /etc/systemd/system/mayak-agent.service /opt/amnezia/awg /opt/amnezia/xray /etc/wireguard/*.conf /etc/amnezia/*; do if test -e \"$p\"; then echo MAYAK_EXISTING_ARTIFACT; fi; done'", TimeSpan.FromSeconds(10)).Output;
            hasArtifacts = artifacts.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any();

            var units = RunProbe(shell, shell.Sudo + "systemctl list-units --all --type=service --no-legend", TimeSpan.FromSeconds(15)).Output;
            hasVpnService = Regex.IsMatch(units, @"(?im)^\s*[^\s]*(?:mayak-agent|amnezia|awg|xray|wireguard|openvpn|wg-quick)[^\s]*\.service\b");

            var links = RunProbe(shell, "ip -o link show", TimeSpan.FromSeconds(10)).Output;
            if (!ProvisioningRules.ValidInterfaceTable(links)) throw new ProvisioningException("Ambiguous interface probe");
            hasVpnInterface = Regex.IsMatch(links, @"(?im)^\s*\d+:\s*(?:awg|wg|tun|tap)[A-Za-z0-9_.-]*:");
            var wgInterfaces = RunProbe(shell, shell.Sudo + "sh -c 'if command -v wg >/dev/null 2>&1; then wg show interfaces || exit 52; else echo __NO_WG_TOOL__; fi'", TimeSpan.FromSeconds(10)).Output.Trim();
            hasWireGuardConfig = wgInterfaces != "__NO_WG_TOOL__" && wgInterfaces.Length > 0;
        }
        catch (Exception)
        {
            return new ProvisioningInspection(false, "Read-only проверка не смогла надёжно подтвердить пустое состояние сервера.", os, version, "unknown", false, plan.AwgPort, plan.XrayPort, plan.BootstrapIdentity);
        }

        bool osOk = os == "ubuntu" && version is "22.04" or "24.04";
        bool archOk = arch == "x86_64";
        bool occupied = hasContainers || hasArtifacts || hasVpnService || hasVpnInterface || hasWireGuardConfig;
        bool busy = ProvisioningRules.IsOccupied(sockets, plan.AwgPort, tcp: false) || ProvisioningRules.IsOccupied(sockets, plan.XrayPort, tcp: true);
        // Занятые порты на занятом сервере обычно держит тот самый прежний VPN: их проверяем повторно после перезаписи.
        string? reason = !osOk ? "Поддерживаются только Ubuntu 22.04 и 24.04." :
            !archOk ? "Поддерживается только архитектура x86_64." :
            busy && !occupied ? "Один из необходимых портов уже занят." : null;
        return new ProvisioningInspection(reason == null, reason, os, version, arch, rootOrSudo, plan.AwgPort, plan.XrayPort, plan.BootstrapIdentity, occupied);
    }

    /// <summary>
    /// Перезапись занятого сервера. Сначала архив прежних настроек в /root/mayak-overwrite-&lt;время&gt;.tar.gz (0600),
    /// затем удаление: агент Маяка, все контейнеры docker/podman, службы VPN (wg-quick, awg-quick, openvpn, xray, v2ray,
    /// amnezia), интерфейсы wg/awg/tun/tap, каталоги Amnezia и конфиги WireGuard. Ничего не печатает, кроме меток шагов.
    /// </summary>
    public const string OverwriteScript = """
        set -u
        umask 077
        stamp=$(date -u +%Y%m%d-%H%M%S)
        keep=""
        for p in /opt/amnezia /etc/amnezia /etc/wireguard /etc/amnezia-wg /etc/mayak /etc/systemd/system/mayak-agent.service; do [ -e "$p" ] && keep="$keep $p"; done
        if [ -n "$keep" ]; then tar czf "/root/mayak-overwrite-$stamp.tar.gz" $keep 2>/dev/null; echo STEP_ARCHIVED; fi
        systemctl disable --now mayak-agent >/dev/null 2>&1
        rm -f /etc/systemd/system/mayak-agent.service /etc/mayak/agent.json
        for r in docker podman; do
          if command -v "$r" >/dev/null 2>&1; then ids=$("$r" ps -aq); [ -n "$ids" ] && "$r" rm -f $ids >/dev/null 2>&1; fi
        done
        echo STEP_CONTAINERS
        for u in $(systemctl list-units --all --type=service --no-legend --plain | awk '{print $1}' | grep -E '^(wg-quick@|awg-quick@|openvpn|xray|v2ray|amnezia|awg)[^ ]*\.service$'); do
          systemctl disable --now "$u" >/dev/null 2>&1
        done
        systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1
        echo STEP_SERVICES
        for i in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(awg|wg|tun|tap)[A-Za-z0-9_.-]*$'); do ip link delete "$i" >/dev/null 2>&1; done
        rm -rf /opt/amnezia /etc/amnezia /etc/amnezia-wg
        rm -f /etc/wireguard/*.conf
        echo STEP_DONE
        """;

    internal static void Overwrite(IShell shell)
    {
        var tmp = shell.UploadTemp(OverwriteScript, ".sh");
        CommandResult result;
        try { result = shell.Run($"{shell.Sudo}bash {SshConnection.Q(tmp)}", TimeSpan.FromMinutes(5)); }
        finally { shell.Run($"rm -f {SshConnection.Q(tmp)}"); }
        if (!result.Output.Contains("STEP_DONE", StringComparison.Ordinal))
            throw new ProvisioningException("Overwrite of the existing server state did not complete");
    }

    private static CommandResult RunProbe(IShell shell, string command, TimeSpan timeout)
    {
        var result = shell.Run(command, timeout);
        if (!result.Ok) throw new ProvisioningException("A read-only inspection command failed");
        return result;
    }

    private static void EnsureInstallable(ProvisioningInspection result)
    {
        if (!result.Supported) throw new ProvisioningException(result.Reason ?? "Target failed read-only preflight");
    }

    /// <summary>
    /// Финальная проверка перед установкой. Занятый сервер перезаписывается, только если это подтверждено при запуске,
    /// и после перезаписи должен пройти проверку как пустой (иначе установка останавливается).
    /// </summary>
    internal static async Task PrepareTargetAsync(IShell ssh, ProvisioningPlan plan, bool overwrite, Func<string, Task> progress)
    {
        var preflight = InspectConnected(ssh, plan);
        EnsureInstallable(preflight);
        if (!preflight.Occupied) return;
        if (!overwrite) throw new ProvisioningException("Target is not empty and overwrite was not confirmed");
        await progress("overwriting");
        Overwrite(ssh);
        var after = InspectConnected(ssh, plan);
        EnsureInstallable(after);
        if (after.Occupied) throw new ProvisioningException("Target still has containers, VPN or agent after overwrite");
    }

    public static bool IdentityMatches(ServerEndpoint actual, string actualPrivate, ServerEndpoint expected, string expectedPrivate)
    {
        actual.Host = "";
        expected.Host = "";
        return actualPrivate == expectedPrivate && JsonSerializer.Serialize(actual) == JsonSerializer.Serialize(expected);
    }

    public static bool XrayMatches(XrayEndpoint actual, XrayEndpoint expected) => JsonSerializer.Serialize(actual) == JsonSerializer.Serialize(expected);
}

public sealed class ProvisioningException(string message) : Exception(message);
