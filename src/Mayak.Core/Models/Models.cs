using System.Text.Json.Serialization;
using Mayak.Core.Awg;

namespace Mayak.Core.Models;

/// <summary>Тип устройства определяет формат файла по умолчанию.</summary>
public enum DeviceKind
{
    Windows,
    Android,
    IPhone,
    Mac,
    Linux,
    Other,
}

public enum ConfigFormat
{
    /// <summary>Ключ vpn:// в файле .vpn — для приложения AmneziaVPN (Windows, Android).</summary>
    AmneziaVpn,
    /// <summary>Конфиг AmneziaWG .conf — для iPhone и Mac.</summary>
    AwgConf,
}

public static class DeviceKindExtensions
{
    public static ConfigFormat DefaultFormat(this DeviceKind kind) => kind switch
    {
        DeviceKind.IPhone or DeviceKind.Mac => ConfigFormat.AwgConf,
        _ => ConfigFormat.AmneziaVpn,
    };

    public static string Title(this DeviceKind kind) => kind switch
    {
        DeviceKind.Windows => "Windows",
        DeviceKind.Android => "Android",
        DeviceKind.IPhone => "iPhone",
        DeviceKind.Mac => "Mac",
        DeviceKind.Linux => "Linux",
        _ => "Другое",
    };

    /// <summary>Apple-клиенты лучше работают с MTU 1280, остальным подходит 1376 (как в Amnezia).</summary>
    public static string Mtu(this DeviceKind kind) => kind is DeviceKind.IPhone or DeviceKind.Mac or DeviceKind.Android ? "1280" : "1376";
}

/// <summary>База Маяка. Хранится на сервере: /opt/amnezia/awg/mayak.json (внутри контейнера).</summary>
public sealed class MayakDatabase
{
    public int SchemaVersion { get; set; } = 1;
    public string ServerTitle { get; set; } = "Маяк VPN";
    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "1.0.0.1";

    /// <summary>Адрес сервера в конфигах клиентов (IP или домен). Пусто — тот же, что для SSH.</summary>
    public string EndpointHost { get; set; } = "";

    /// <summary>Лимит по умолчанию для новых устройств, Мбит/с. 35 — с запасом для 4K на YouTube.</summary>
    public int DefaultDownMbps { get; set; } = 35;
    public int DefaultUpMbps { get; set; } = 35;

    public List<VpnUser> Users { get; set; } = new();

    /// <summary>Служебная учётка для встроенной проверки протоколов (не показывается в списке пользователей).</summary>
    public ProbeIdentity? Probe { get; set; }

    [JsonIgnore]
    public IEnumerable<VpnDevice> AllDevices => Users.SelectMany(u => u.Devices);

    public VpnUser? FindUserByDevice(VpnDevice device) => Users.FirstOrDefault(u => u.Devices.Contains(device));
}

public sealed class VpnUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Note { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool Enabled { get; set; } = true;
    public List<VpnDevice> Devices { get; set; } = new();
}

public sealed class VpnDevice
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public DeviceKind Kind { get; set; } = DeviceKind.Other;

    /// <summary>Приватный ключ клиента. Хранится, чтобы можно было перевыпустить файл. Пусто для привязанных чужих подключений.</summary>
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string Ip { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool Enabled { get; set; } = true;

    /// <summary>UUID клиента Xray (VLESS). Пусто — Xray для устройства не выдан.</summary>
    public string XrayId { get; set; } = "";

    /// <summary>Лимит скачивания, Мбит/с. 0 — без ограничения.</summary>
    public int DownMbps { get; set; }
    /// <summary>Лимит отдачи, Мбит/с. 0 — без ограничения.</summary>
    public int UpMbps { get; set; }

    [JsonIgnore]
    public bool CanExport => !string.IsNullOrEmpty(PrivateKey);
}

/// <summary>Всё, что нужно для сборки клиентского конфига.</summary>
public sealed class ServerEndpoint
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string ServerPublicKey { get; set; } = "";
    public string PresharedKey { get; set; } = "";
    public string SubnetAddress { get; set; } = "10.8.1.0";
    public string SubnetCidr { get; set; } = "24";
    public AwgParameters Parameters { get; set; } = new();
}

/// <summary>Статистика пира из «awg show awg0 dump».</summary>
public sealed class PeerStats
{
    public string PublicKey { get; set; } = "";
    public string? Endpoint { get; set; }
    public DateTime? LatestHandshake { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }

    public bool IsOnline => LatestHandshake.HasValue && DateTime.UtcNow - LatestHandshake.Value < TimeSpan.FromMinutes(3);
}

/// <summary>Пир, созданный не Маяком (например, официальным приложением AmneziaVPN).</summary>
public sealed class ForeignPeer
{
    public string PublicKey { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>Ключи служебной «проверочной» учётки Маяка.</summary>
public sealed class ProbeIdentity
{
    public string AwgPrivateKey { get; set; } = "";
    public string AwgPublicKey { get; set; } = "";
    public string AwgIp { get; set; } = "";
    public string XrayId { get; set; } = "";
}

/// <summary>Параметры Xray (VLESS + Reality), прочитанные с сервера.</summary>
public sealed class XrayEndpoint
{
    public int Port { get; set; } = 443;
    public string PublicKey { get; set; } = "";
    public string ShortId { get; set; } = "";
    /// <summary>Сайт-маскировка Reality (SNI).</summary>
    public string Sni { get; set; } = XrayDefaults.DefaultSni;
    /// <summary>xhttp или raw (tcp).</summary>
    public string Transport { get; set; } = "xhttp";
    public string XhttpPath { get; set; } = "/";
    public string XhttpHost { get; set; } = "";
    public string XhttpMode { get; set; } = "auto";
    /// <summary>xtls-rprx-vision для raw, пусто для xhttp.</summary>
    public string Flow { get; set; } = "";
    public string Fingerprint { get; set; } = "chrome";

    public string Title => Transport == "xhttp" ? "VLESS + Reality + XHTTP" : "VLESS + Reality";
}

public static class XrayDefaults
{
    /// <summary>Версия Xray-core — та же, что закреплена в AmneziaVPN.</summary>
    public const string Release = "v26.7.28";
    /// <summary>SHA-256 Xray-linux-64.zip из официального релиза (файл .dgst).</summary>
    public const string LinuxZipSha256 = "8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40";
    /// <summary>SHA-256 Xray-windows-64.zip из официального релиза (файл .dgst).</summary>
    public const string WindowsZipSha256 = "c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1";
    public const string DefaultSni = "www.googletagmanager.com";
    public const int DefaultPort = 443;
}
