using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Core.Models;

namespace Mayak.Core.Export;

/// <summary>Собирает файлы для подключения: .conf (AmneziaWG) и vpn:// (.vpn, AmneziaVPN).</summary>
public static class ClientConfigFactory
{
    public const string ContainerName = "amnezia-awg2";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>Текст конфига AmneziaWG. mtu = null — строка MTU не пишется (так делает Amnezia внутри vpn://).</summary>
    public static string BuildNativeConfig(ServerEndpoint server, VpnDevice device, string dns1, string dns2, string? mtu)
    {
        EnsureExportable(device);
        var sb = new StringBuilder();
        sb.Append("[Interface]\n");
        sb.Append($"Address = {device.Ip}/32\n");
        sb.Append($"DNS = {JoinDns(dns1, dns2)}\n");
        sb.Append($"PrivateKey = {device.PrivateKey}\n");
        if (!string.IsNullOrEmpty(mtu)) sb.Append($"MTU = {mtu}\n");
        foreach (var line in server.Parameters.ClientInterfaceLines())
            sb.Append(line).Append('\n');
        sb.Append('\n');
        sb.Append("[Peer]\n");
        sb.Append($"PublicKey = {server.ServerPublicKey}\n");
        sb.Append($"PresharedKey = {server.PresharedKey}\n");
        sb.Append("AllowedIPs = 0.0.0.0/0, ::/0\n");
        sb.Append($"Endpoint = {FormatHost(server.Host)}:{server.Port}\n");
        sb.Append($"PersistentKeepalive = {server.Parameters.PersistentKeepalive}\n");
        return sb.ToString();
    }

    /// <summary>.conf для iPhone/Mac/Linux — с MTU для типа устройства.</summary>
    public static string BuildConfFile(ServerEndpoint server, VpnDevice device, string dns1, string dns2) =>
        BuildNativeConfig(server, device, dns1, dns2, device.Kind.Mtu());

    /// <summary>JSON сервера в формате AmneziaVPN (то, что лежит внутри vpn://).</summary>
    public static string BuildAmneziaJson(ServerEndpoint server, VpnDevice device, string dns1, string dns2, string description)
    {
        EnsureExportable(device);
        var p = server.Parameters;

        var lastConfig = new JsonObject
        {
            ["config"] = BuildNativeConfig(server, device, dns1, dns2, mtu: null),
            ["hostName"] = server.Host,
            ["port"] = server.Port,
            ["client_ip"] = device.Ip,
            ["client_priv_key"] = device.PrivateKey,
            ["client_pub_key"] = device.PublicKey,
            ["server_pub_key"] = server.ServerPublicKey,
            ["psk_key"] = server.PresharedKey,
            ["clientId"] = device.PublicKey,
            ["allowed_ips"] = new JsonArray("0.0.0.0/0", "::/0"),
            ["persistent_keep_alive"] = p.PersistentKeepalive,
            ["mtu"] = device.Kind.Mtu(),
        };
        foreach (var (k, v) in p.JsonPairs())
            lastConfig[k] = v;

        var awg = new JsonObject
        {
            ["port"] = server.Port.ToString(),
            ["transport_proto"] = "udp",
            ["protocol_version"] = p.ProtocolVersionString,
            ["subnet_address"] = server.SubnetAddress,
            ["subnet_cidr"] = server.SubnetCidr,
        };
        foreach (var (k, v) in p.JsonPairs())
            awg[k] = v;
        awg["last_config"] = lastConfig.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

        var root = new JsonObject
        {
            ["containers"] = new JsonArray(new JsonObject
            {
                ["awg"] = awg,
                ["container"] = ContainerName,
            }),
            ["defaultContainer"] = ContainerName,
            ["description"] = description,
            ["dns1"] = dns1,
            ["dns2"] = dns2,
            ["hostName"] = server.Host,
        };
        return root.ToJsonString(JsonOptions);
    }

    /// <summary>Ключ vpn:// — его же сохраняем в файл .vpn.</summary>
    public static string BuildVpnKey(ServerEndpoint server, VpnDevice device, string dns1, string dns2, string description) =>
        VpnKeyCodec.Encode(BuildAmneziaJson(server, device, dns1, dns2, description));

    /// <summary>Набор QR-кодов, которые сканирует приложение AmneziaVPN.</summary>
    public static IReadOnlyList<string> BuildAmneziaQrChunks(ServerEndpoint server, VpnDevice device, string dns1, string dns2, string description) =>
        VpnKeyCodec.AmneziaQrChunks(BuildAmneziaJson(server, device, dns1, dns2, description));

    /// <summary>Имя файла: для .vpn — читаемое, для .conf — латиница до 15 символов (требование WireGuard к имени туннеля).</summary>
    public static string SuggestFileName(string userName, VpnDevice device, ConfigFormat format)
    {
        if (format == ConfigFormat.AmneziaVpn)
        {
            var name = $"{userName} - {device.Name}";
            foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
            return name + ".vpn";
        }

        var latin = Transliteration.ToTunnelName($"{userName}-{device.Name}");
        return latin + ".conf";
    }

    private static string JoinDns(string dns1, string dns2) =>
        string.IsNullOrWhiteSpace(dns2) ? dns1 : $"{dns1}, {dns2}";

    private static string FormatHost(string host) =>
        host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;

    private static void EnsureExportable(VpnDevice device)
    {
        if (!device.CanExport)
            throw new InvalidOperationException("У этого устройства нет приватного ключа (подключение создано не Маяком). Выпустите новое устройство.");
    }
}
