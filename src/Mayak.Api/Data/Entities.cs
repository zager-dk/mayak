using Mayak.Core.Models;

namespace Mayak.Api.Data;

public static class Roles
{
    public const string User = "user";
    public const string Support = "support";
    public const string Admin = "admin";
    public const string Owner = "owner";

    public static readonly string[] All = { User, Support, Admin, Owner };

    public static int Rank(string role) => role switch
    {
        Owner => 3,
        Admin => 2,
        Support => 1,
        _ => 0,
    };
}

/// <summary>Аккаунт человека. Минимум данных: Telegram ID или почта, тариф, срок.</summary>
public sealed class Account
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public long? TelegramId { get; set; }
    public string? TelegramUsername { get; set; }
    public string? Email { get; set; }
    public string? LoginEmailNormalized { get; set; }
    public string? PasswordHash { get; set; }
    public string Role { get; set; } = Roles.User;
    public bool Enabled { get; set; } = true;
    public string Note { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Доступ оплачен до (UTC). null — без срока (свои люди).</summary>
    public DateTime? PaidUntil { get; set; }
    public int MaxDevices { get; set; } = 3;
    public int DownMbps { get; set; } = 35;
    public int UpMbps { get; set; } = 35;

    /// <summary>Перенесён из Маяка для Windows (у его устройств есть приватные ключи для повторной выдачи файла).</summary>
    public bool Legacy { get; set; }

    /// <summary>
    /// Ключ подписки для приложения Маяк (auth_data.api_key протокола шлюза). Приложение само создаёт
    /// ключ устройства и получает настройки по нему. null — ещё не выдавался.
    /// </summary>
    public string? AppKey { get; set; }

    public List<Device> Devices { get; set; } = new();

    public bool IsActive(DateTime now) => Enabled && (PaidUntil == null || PaidUntil > now);
}

/// <summary>Устройство. Ключ AmneziaWG создаёт само приложение; на сервер приходит только открытый.</summary>
public sealed class Device
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AccountId { get; set; }
    public Account? Account { get; set; }
    public string Name { get; set; } = "";
    public DeviceKind Kind { get; set; } = DeviceKind.Other;
    public string AwgPublicKey { get; set; } = "";
    /// <summary>Только у перенесённых из Маяка для Windows: чтобы выдать файл заново.</summary>
    public string? AwgPrivateKey { get; set; }
    public string Ip { get; set; } = "";
    public string XrayId { get; set; } = "";
    public bool Enabled { get; set; } = true;
    /// <summary>Свой лимит устройства, Мбит/с; null — по тарифу аккаунта.</summary>
    public int? DownMbps { get; set; }
    public int? UpMbps { get; set; }
    /// <summary>Установка приложения Маяк (installation_uuid) — у устройств, подключённых через приложение.</summary>
    public string? InstallationId { get; set; }
    /// <summary>SHA-256 токена устройства (md1.…) для шлюза; сам токен не хранится. null — устройство работает по ключу аккаунта.</summary>
    public string? AppTokenHash { get; set; }
    /// <summary>SHA-256 от постоянного ID устройства (ANDROID_ID, MachineGuid), посчитанный приложением: переустановка не занимает новое место.</summary>
    public string? StableDeviceHash { get; set; }
    /// <summary>SHA-256 предыдущего ключа этой установки (прежний токен или ключ аккаунта): им можно только завершить старые попытки подключения.</summary>
    public string? PreviousAppTokenHash { get; set; }
    /// <summary>SHA-256 of the current per-device subscription token; the token itself is never stored.</summary>
    public string? SubscriptionTokenHash { get; set; }
    public string? OsVersion { get; set; }
    public string? AppVersion { get; set; }
    /// <summary>Explicit opt-in assignment to the managed VLESS pool. Null preserves legacy behavior.</summary>
    public string? ServiceProtocol { get; set; }
    public Guid? ExitEndpointId { get; set; }
    public long CredentialsRevision { get; set; }
    /// <summary>Когда приложение последний раз получало настройки.</summary>
    public DateTime? ConfigFetchedAt { get; set; }
    /// <summary>Explicit client opt-in for shared-AWG admission accounting.</summary>
    public bool AutoConnectManaged { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastHandshake { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
}

/// <summary>Public VLESS/Reality exit metadata and protocol-specific agent readiness.</summary>
public sealed class ExitEndpoint
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ServerId { get; set; }
    public Server? Server { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 443;
    public string PublicKey { get; set; } = "";
    public string Sni { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Transport { get; set; } = "tcp";
    public string Fingerprint { get; set; } = "chrome";
    public string XhttpPath { get; set; } = "/";
    public string XhttpHost { get; set; } = "";
    public string XhttpMode { get; set; } = "auto";
    public long IdentityVersion { get; set; } = 1;
    public bool AllowNewConnections { get; set; }
    public int CapacitySlots { get; set; } = 1;
    public long AppliedCredentialsRevision { get; set; }
    /// <summary>Fingerprint of effective desired pool membership; empty bootstrap is SHA-256 of [].</summary>
    public string DesiredCredentialsHash { get; set; } = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945";
    public DateTime? ProtocolReportReceivedAt { get; set; }
    public long ReportedIdentityVersion { get; set; }
    public long ReportedCredentialsRevision { get; set; }
    public bool RuntimeReady { get; set; }
    public bool ConfigValid { get; set; }
    public bool SelfTestPassed { get; set; }
    public bool DryRun { get; set; }
    public string? ProtocolError { get; set; }
    public int OccupiedSlots { get; set; }
}

public static class ServerRoles
{
    public const string Exit = "exit";
    public const string Entry = "entry";
}

/// <summary>Сервер сети: выход за рубежом или вход в России. Управляется агентом.</summary>
public sealed class Server
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Role { get; set; } = ServerRoles.Exit;
    public string Host { get; set; } = "";
    public string City { get; set; } = "";
    public string Country { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string Fact { get; set; } = "";
    public string? PhotoUrl { get; set; }
    /// <summary>SHA-256 токена агента (сам токен показывается один раз).</summary>
    public string AgentTokenHash { get; set; } = "";
    /// <summary>Выход, через который сейчас идёт трафик.</summary>
    public bool Active { get; set; }
    /// <summary>Для входа: на какой выход пересылать.</summary>
    public Guid? TargetExitId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastSeen { get; set; }
    public string? AgentVersion { get; set; }
    public string? LastError { get; set; }
    /// <summary>Последний отчёт агента (JSON): пиры, проверки.</summary>
    public string? LastReport { get; set; }
    /// <summary>Безопасный статус автоматической установки; SSH credentials здесь не хранятся.</summary>
    public string? ProvisioningStatus { get; set; }
    public string? ProvisioningMessage { get; set; }
    public DateTime? ProvisioningUpdatedAt { get; set; }
    public string? TrustedHostFingerprint { get; set; }
    public bool ProvisionIdentityMatched { get; set; }
    public string? ProvisioningIdentityHash { get; set; }
    public long? ProvisioningConfirmedRevision { get; set; }
    public DateTime? ProvisioningConfirmedAt { get; set; }
    /// <summary>Explicitly approved native shared-AWG candidate policy.</summary>
    public bool AutoSelectEnabled { get; set; }
    public int NativeCapacity { get; set; } = 50;
    /// <summary>Validated public IPv4 egress allowlist, JSON array.</summary>
    public string ExpectedEgressIpsJson { get; set; } = "[]";
}

/// <summary>
/// Проверка доступности сервера с API (Москва): ICMP, TCP-порт Xray, TLS-рукопожатие с SNI маскировки.
/// Только итог и задержка; адресов пользователей и трафика здесь нет. Хранится 7 дней.
/// </summary>
public sealed class ServerProbe
{
    public long Id { get; set; }
    public Guid ServerId { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
    /// <summary>icmp, tcp, tls (этап A); awg, xray (этап B — через туннели).</summary>
    public string Kind { get; set; } = "";
    public bool Ok { get; set; }
    public int? LatencyMs { get; set; }
    /// <summary>Короткий код ошибки (timeout, refused, unavailable…), без адресов.</summary>
    public string? Error { get; set; }
}

/// <summary>
/// Последние счётчики пира AWG на сервере (из отчёта агента): база для подсчёта прироста трафика.
/// Ключ — открытый ключ пира; адресов пользователей здесь нет.
/// </summary>
public sealed class PeerCounter
{
    public Guid ServerId { get; set; }
    public string PublicKey { get; set; } = "";
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
    public DateTime? LastHandshake { get; set; }
    public DateTime At { get; set; }
}

/// <summary>
/// История использования устройства на сервере выхода: только объём и время в сети.
/// Span = 1 — час (Bucket — начало часа UTC, хранится 14 дней), Span = 24 — сутки по Москве
/// (Bucket — полночь МСК в UTC, хранится 1 год). Rx — от пользователя к серверу, Tx — от сервера к пользователю.
/// </summary>
public sealed class DeviceUsage
{
    public Guid DeviceId { get; set; }
    public Guid ServerId { get; set; }
    public short Span { get; set; }
    public DateTime Bucket { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
    public int OnlineSeconds { get; set; }
    /// <summary>Из них через Xray (подмножество RxBytes/TxBytes).</summary>
    public long XrayRxBytes { get; set; }
    public long XrayTxBytes { get; set; }
}

/// <summary>История сервера выхода (все пиры, включая не опознанные): объём, пик и сумма времени подключённых.</summary>
public sealed class ServerUsage
{
    public Guid ServerId { get; set; }
    public short Span { get; set; }
    public DateTime Bucket { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
    public int PeakPeers { get; set; }
    public long PeerSeconds { get; set; }
    public int Reports { get; set; }
    /// <summary>Из них через Xray (подмножество RxBytes/TxBytes).</summary>
    public long XrayRxBytes { get; set; }
    public long XrayTxBytes { get; set; }
    /// <summary>Нагрузка (агент 0.2+): сумма и число замеров процессора — среднее = CpuSum / CpuSamples.</summary>
    public int CpuSamples { get; set; }
    public double CpuSum { get; set; }
    public double CpuMax { get; set; }
    public double Load1Max { get; set; }
    public long MemUsedMax { get; set; }
    public long MemTotal { get; set; }
    /// <summary>Байты сетевого интерфейса сервера (весь трафик машины, VPN учитывается дважды: вход и выход).</summary>
    public long NetRxBytes { get; set; }
    public long NetTxBytes { get; set; }
    /// <summary>Свободно на диске по последнему замеру в интервале.</summary>
    public long DiskFree { get; set; }
    public long DiskTotal { get; set; }
}

/// <summary>Cooperative native-client slot allocation; it does not enforce traffic limits.</summary>
public sealed class AwgAllocation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DeviceId { get; set; }
    public Guid ServerId { get; set; }
    public string AttemptId { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ProvenAt { get; set; }
    public DateTime? ReleasedAt { get; set; }
    /// <summary>SHA-256 ключа, которым открыто место: им же его можно закрыть и после смены ключа устройства.</summary>
    public string? AuthKeyHash { get; set; }
}

/// <summary>
/// Общие для всех выходов ключи и параметры: выходы — клоны, поэтому пользователь
/// не замечает переключения. Одна строка (Id = 1).
/// </summary>
public sealed class ClusterIdentity
{
    public int Id { get; set; } = 1;
    /// <summary>ServerEndpoint без адреса: ключ сервера, PSK, порт, подсеть, параметры AWG (JSON).</summary>
    public string AwgJson { get; set; } = "";
    public string AwgServerPrivateKey { get; set; } = "";
    /// <summary>XrayEndpoint (JSON) и закрытый ключ Reality; пусто — Xray нет.</summary>
    public string? XrayJson { get; set; }
    public string? XrayPrivateKey { get; set; }
    /// <summary>
    /// Отпечаток uTLS для клиентов (ссылки, подписка, vpn://). Пусто — ClusterService.DefaultClientFingerprint (firefox).
    /// Хранится отдельно и НЕ входит в identity выхода (IdentityHash/IdentityMatches): серверу Xray он безразличен,
    /// а правка XrayJson делает выходы неподтверждёнными (инцидент 10.11.2026).
    /// </summary>
    public string? XrayClientFingerprint { get; set; }
    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "1.0.0.1";
    /// <summary>Адрес для пользователей: вход или домен. Пусто — адрес активного выхода.</summary>
    public string PublicHost { get; set; } = "";
    public string Title { get; set; } = "Маяк VPN";
    /// <summary>Растёт при любом изменении, влияющем на серверы: агенты сверяются по нему.</summary>
    public long Revision { get; set; } = 1;
}

/// <summary>Вход через Telegram: приложение создаёт запрос, человек подтверждает его в боте.</summary>
public sealed class LoginRequest
{
    public string Id { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public long? TelegramId { get; set; }
    public string? TelegramUsername { get; set; }
    public string? TelegramName { get; set; }
    public Guid? AccountId { get; set; }
    public bool Consumed { get; set; }
    /// <summary>Сколько раз по запросу выдан сеанс: вход может завершить и исходная вкладка, и кнопка из бота.</summary>
    public int Uses { get; set; }
    /// <summary>Куда вернуть человека кнопкой из бота: /my/ или /admin/.</summary>
    public string? ReturnPath { get; set; }
    /// <summary>Хеш кода приглашения, если человек пришёл по ссылке из админки.</summary>
    public string? InviteHash { get; set; }
    /// <summary>Запрос привязки Telegram к уже вошедшему аккаунту (почта и пароль): бот не создаёт новый аккаунт.</summary>
    public Guid? LinkAccountId { get; set; }
}

/// <summary>
/// Приглашение: ссылка, по которой человек входит через Telegram и получает уже заведённый аккаунт
/// (например, перенесённый из Маяка для Windows — со всеми устройствами). Одноразовое.
/// </summary>
public sealed class Invite
{
    public string CodeHash { get; set; } = "";
    public Guid AccountId { get; set; }
    public Account? Account { get; set; }
    public Guid? CreatedBy { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddDays(14);
    public DateTime? UsedAt { get; set; }
}

/// <summary>Сеанс приложения: хранится только хеш токена.</summary>
public sealed class Session
{
    public string TokenHash { get; set; } = "";
    public Guid AccountId { get; set; }
    public Account? Account { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastUsed { get; set; } = DateTime.UtcNow;
    public string Client { get; set; } = "";
}

/// <summary>Журнал действий администраторов и агентов.</summary>
public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
    public Guid? ActorId { get; set; }
    public string Action { get; set; } = "";
    public string Details { get; set; } = "";
}
