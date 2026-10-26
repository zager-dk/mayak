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
