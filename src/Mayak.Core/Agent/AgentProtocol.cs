using Mayak.Core.Models;
using Mayak.Core.Server;

namespace Mayak.Core.Agent;

/// <summary>
/// Протокол агента и API (JSON по HTTPS, токен агента в заголовке Authorization: Bearer).
/// Агент сам ходит в API: так серверами можно управлять, даже когда SSH до них не проходит.
/// </summary>
public static class AgentPaths
{
    public const string Hello = "agent/v1/hello";
    public const string State = "agent/v1/state";
    public const string Report = "agent/v1/report";
}

/// <summary>Первое сообщение агента после запуска.</summary>
public sealed class AgentHello
{
    public string Version { get; set; } = "";
    /// <summary>Адрес сервера, как его видит сам сервер (для проверки).</summary>
    public string Hostname { get; set; } = "";
    /// <summary>Ключи и параметры уже настроенного выхода — становятся общими для всех выходов, если их ещё нет.</summary>
    public AgentIdentity? Identity { get; set; }
    /// <summary>Пользователи Маяка для Windows с этого сервера — переносятся в API один раз, пока в нём нет устройств.</summary>
    public MayakDatabase? Legacy { get; set; }
    /// <summary>Адреса в VPN-подсети, занятые не Маяком (служебная учётка, подключения из AmneziaVPN).</summary>
    public List<string> ReservedIps { get; set; } = new();
}

public sealed class AgentIdentity
{
    public ServerEndpoint Awg { get; set; } = new();
    public string AwgServerPrivateKey { get; set; } = "";
    public XrayEndpoint? Xray { get; set; }
    public string? XrayPrivateKey { get; set; }
    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "1.0.0.1";
    public string Title { get; set; } = "Маяк VPN";
}

public sealed class AgentHelloReply
{
    public Guid ServerId { get; set; }
    public string Name { get; set; } = "";
    public string Role { get; set; } = "";
    public int ImportedDevices { get; set; }
}

/// <summary>Желаемое состояние сервера.</summary>
public sealed class AgentState
{
    public long Revision { get; set; }
    public string Role { get; set; } = "";
    public int DefaultDownMbps { get; set; }
    public int DefaultUpMbps { get; set; }
    public List<AgentAccount> Accounts { get; set; } = new();
    /// <summary>Endpoint-level VLESS desired state, sent even when there are no assigned devices.</summary>
    public AgentPoolEndpoint? PoolEndpoint { get; set; }
    /// <summary>Per-device credentials assigned to this endpoint.</summary>
    public List<AgentPoolDevice> PoolDevices { get; set; } = new();
    /// <summary>Для входа: куда пересылать трафик. null — пересылка выключена.</summary>
    public AgentRelay? Relay { get; set; }
    /// <summary>Как часто приходить за состоянием, секунд.</summary>
    public int PollSeconds { get; set; } = 30;
}

public sealed class AgentPoolEndpoint
{
    public Guid EndpointId { get; set; }
    public long IdentityVersion { get; set; }
    public long DesiredCredentialsRevision { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string PublicKey { get; set; } = "";
    public string Sni { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Transport { get; set; } = "";
    public string Fingerprint { get; set; } = "chrome";
    public string XhttpPath { get; set; } = "/";
    public string XhttpHost { get; set; } = "";
    public string XhttpMode { get; set; } = "auto";
    public bool AllowNewConnections { get; set; }
    public int CapacitySlots { get; set; }
}

public sealed class AgentPoolDevice
{
    public Guid DeviceId { get; set; }
    public bool Enabled { get; set; }
    public string XrayId { get; set; } = "";
    public long CredentialsRevision { get; set; }
    public Guid EndpointId { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string PublicKey { get; set; } = "";
    public string Sni { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Transport { get; set; } = "";
    public string Fingerprint { get; set; } = "chrome";
    public string XhttpPath { get; set; } = "/";
    public string XhttpHost { get; set; } = "";
    public string XhttpMode { get; set; } = "auto";
}

public sealed class AgentAccount
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public List<AgentDevice> Devices { get; set; } = new();
}

public sealed class AgentDevice
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public DeviceKind Kind { get; set; }
    public string PublicKey { get; set; } = "";
    public string Ip { get; set; } = "";
    public string XrayId { get; set; } = "";
    public bool Enabled { get; set; }
    public int DownMbps { get; set; }
    public int UpMbps { get; set; }
}

public sealed class AgentRelay
{
    public string TargetHost { get; set; } = "";
    public int AwgPort { get; set; }
    public int? XrayPort { get; set; }
}

/// <summary>Отчёт агента после применения состояния.</summary>
public sealed class AgentReport
{
    public long AppliedRevision { get; set; }
    public string? Error { get; set; }
    public DesiredStateResult? Result { get; set; }
    public List<AgentPeerStats> Peers { get; set; } = new();
    public List<string> ReservedIps { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    /// <summary>Агент в пробном режиме: показывает, что изменил бы, но сервер не трогает.</summary>
    public bool DryRun { get; set; }
    public DateTime? At { get; set; }
    /// <summary>Protocol-specific evidence. API receipt time is authoritative.</summary>
    public string? Protocol { get; set; }
    public long IdentityVersion { get; set; }
    public long CredentialsRevision { get; set; }
    public bool RuntimeReady { get; set; }
    public bool ConfigValid { get; set; }
    public bool SelfTestPassed { get; set; }
    /// <summary>Agent proof for provisioned exits: running AWG/Xray services, parsable config, and successful post-apply reread.</summary>
    public ProvisioningRuntimeProof? ProvisioningProof { get; set; }
}

public sealed class ProvisioningRuntimeProof
{
    public bool AwgRunning { get; set; }
    public bool XrayRunning { get; set; }
    public bool ConfigurationLoaded { get; set; }
    public bool PostApplyCheckPassed { get; set; }
}

public sealed class AgentPeerStats
{
    public string PublicKey { get; set; } = "";
    public DateTime? LatestHandshake { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
}

/// <summary>Перевод состояния API в пользователей и устройства ядра Маяка.</summary>
public static class AgentMapping
{
    public static List<VpnUser> ToUsers(AgentState state) => state.Accounts.Select(a => new VpnUser
    {
        Id = a.Id,
        Name = a.Name,
        Enabled = a.Enabled,
        Devices = a.Devices.Select(d => new VpnDevice
        {
            Id = d.Id,
            Name = d.Name,
            Kind = d.Kind,
            PublicKey = d.PublicKey,
            Ip = d.Ip,
            XrayId = d.XrayId,
            Enabled = d.Enabled,
            DownMbps = d.DownMbps,
            UpMbps = d.UpMbps,
        }).ToList(),
    }).ToList();
}
