using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Core.Models;

namespace Mayak.Core.Xray;

/// <summary>
/// Конфиги Xray в формате AmneziaVPN: server.json (inbound VLESS + Reality) и клиентский
/// outbound (last_config в ключе vpn://). Структура повторяет XrayServerConfig::toServerInboundJson
/// и XrayProtocolConfig::toClientOutboundJson из amnezia-client.
/// </summary>
public static class XrayConfig
{
    /// <summary>Префикс email клиента, по которому Маяк узнаёт «свои» записи в server.json.</summary>
    public const string MayakEmailPrefix = "mayak:";
    public const string ProbeEmail = "mayak:probe";
    public const int LocalSocksPort = 10808;

    private static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly JsonSerializerOptions Compact = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public sealed record Client(string Id, string Email, string Flow);

    /// <summary>Новый server.json: VLESS, Reality, XHTTP.</summary>
    public static string BuildServerJson(XrayEndpoint ep, string realityPrivateKey, IEnumerable<Client> clients)
    {
        var stream = new JsonObject
        {
            ["network"] = ep.Transport == "xhttp" ? "xhttp" : "tcp",
            ["security"] = "reality",
            ["realitySettings"] = new JsonObject
            {
                ["dest"] = ep.Sni + ":443",
                ["privateKey"] = realityPrivateKey,
                ["serverNames"] = new JsonArray(ep.Sni),
                ["shortIds"] = new JsonArray(ep.ShortId),
            },
        };
        if (ep.Transport == "xhttp")
        {
            stream["xhttpSettings"] = new JsonObject
            {
                ["host"] = string.IsNullOrEmpty(ep.XhttpHost) ? ep.Sni : ep.XhttpHost,
                ["path"] = ep.XhttpPath,
                ["mode"] = "auto",
            };
        }

        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "error" },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["port"] = ep.Port,
                ["protocol"] = "vless",
                ["settings"] = new JsonObject
                {
                    ["clients"] = ClientsToJson(clients),
                    ["decryption"] = "none",
                },
                ["streamSettings"] = stream,
            }),
            ["outbounds"] = new JsonArray(new JsonObject { ["protocol"] = "freedom" }),
        };
        return root.ToJsonString(Indented);
    }

    public static JsonArray ClientsToJson(IEnumerable<Client> clients)
    {
        var arr = new JsonArray();
        foreach (var c in clients)
        {
            var o = new JsonObject { ["id"] = c.Id };
            if (!string.IsNullOrEmpty(c.Flow)) o["flow"] = c.Flow;
            if (!string.IsNullOrEmpty(c.Email)) o["email"] = c.Email;
            arr.Add(o);
        }
        return arr;
    }

    /// <summary>Закрытый ключ Reality из server.json.</summary>
    public static string? ReadRealityPrivateKey(string json)
    {
        var root = JsonNode.Parse(json)?.AsObject();
        var inbound = root?["inbounds"]?.AsArray().FirstOrDefault()?.AsObject();
        return inbound?["streamSettings"]?["realitySettings"]?["privateKey"]?.GetValue<string>();
    }

    /// <summary>Читает параметры из server.json (в том числе созданного официальным AmneziaVPN).</summary>
    public static XrayEndpoint ParseServerJson(string json, string publicKey)
    {
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new FormatException("server.json пустой");
        var inbound = root["inbounds"]?.AsArray().FirstOrDefault()?.AsObject() ?? throw new FormatException("в server.json нет inbounds");
        var stream = inbound["streamSettings"]?.AsObject() ?? new JsonObject();
        var reality = stream["realitySettings"]?.AsObject();
        var network = stream["network"]?.GetValue<string>() ?? "tcp";
        var xhttp = stream["xhttpSettings"]?.AsObject();

        var ep = new XrayEndpoint
        {
            Port = inbound["port"]?.GetValue<int>() ?? 443,
            PublicKey = publicKey,
            ShortId = reality?["shortIds"]?.AsArray().FirstOrDefault()?.GetValue<string>() ?? "",
            Sni = reality?["serverNames"]?.AsArray().FirstOrDefault()?.GetValue<string>()
                  ?? (reality?["dest"]?.GetValue<string>() ?? XrayDefaults.DefaultSni).Split(':')[0],
            Transport = network == "xhttp" ? "xhttp" : "raw",
            XhttpPath = xhttp?["path"]?.GetValue<string>() ?? "/",
            XhttpHost = xhttp?["host"]?.GetValue<string>() ?? "",
            XhttpMode = xhttp?["mode"]?.GetValue<string>() ?? "auto",
        };
        var firstClient = ReadClients(json).FirstOrDefault();
        if (ep.Transport == "raw") ep.Flow = firstClient?.Flow ?? "xtls-rprx-vision";
        if (stream["security"]?.GetValue<string>() != "reality")
            throw new FormatException("Xray на сервере настроен без Reality — такой вариант Маяк пока не поддерживает");
        return ep;
    }

    public static List<Client> ReadClients(string serverJson)
    {
        var root = JsonNode.Parse(serverJson)?.AsObject();
        var clients = root?["inbounds"]?.AsArray().FirstOrDefault()?["settings"]?["clients"]?.AsArray();
        var list = new List<Client>();
        if (clients == null) return list;
        foreach (var c in clients)
        {
            if (c is not JsonObject o) continue;
            var id = o["id"]?.GetValue<string>();
            if (string.IsNullOrEmpty(id)) continue;
            list.Add(new Client(id, o["email"]?.GetValue<string>() ?? "", o["flow"]?.GetValue<string>() ?? ""));
        }
        return list;
    }

    /// <summary>Заменяет список клиентов в server.json, сохраняя остальное как есть.</summary>
    public static string ReplaceClients(string serverJson, IEnumerable<Client> clients)
    {
        var root = JsonNode.Parse(serverJson)!.AsObject();
        var settings = root["inbounds"]!.AsArray()[0]!["settings"]!.AsObject();
        settings["clients"] = ClientsToJson(clients);
        return root.ToJsonString(Indented);
    }

    /// <summary>Клиентский конфиг Xray (native config AmneziaVPN): SOCKS на 127.0.0.1 + VLESS outbound.</summary>
    public static string BuildClientJson(string host, XrayEndpoint ep, string clientId, int localSocksPort = LocalSocksPort)
    {
        var user = new JsonObject { ["id"] = clientId, ["encryption"] = "none" };
        if (ep.Transport == "raw" && !string.IsNullOrEmpty(ep.Flow)) user["flow"] = ep.Flow;

        var stream = new JsonObject
        {
            ["network"] = ep.Transport == "xhttp" ? "xhttp" : "tcp",
            ["security"] = "reality",
            ["realitySettings"] = new JsonObject
            {
                ["fingerprint"] = ep.Fingerprint,
                ["serverName"] = ep.Sni,
                ["publicKey"] = ep.PublicKey,
                ["shortId"] = ep.ShortId,
                ["spiderX"] = "",
            },
        };
        if (ep.Transport == "xhttp")
        {
            stream["xhttpSettings"] = new JsonObject
            {
                ["host"] = string.IsNullOrEmpty(ep.XhttpHost) ? ep.Sni : ep.XhttpHost,
                ["path"] = ep.XhttpPath,
                ["mode"] = ep.XhttpMode == "" ? "auto" : ep.XhttpMode,
            };
        }

        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "error" },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["listen"] = "127.0.0.1",
                ["port"] = localSocksPort,
                ["protocol"] = "socks",
                ["settings"] = new JsonObject { ["udp"] = true },
            }),
            ["outbounds"] = new JsonArray(new JsonObject
            {
                ["protocol"] = "vless",
                ["settings"] = new JsonObject
                {
                    ["vnext"] = new JsonArray(new JsonObject
                    {
                        ["address"] = host,
                        ["port"] = ep.Port,
                        ["users"] = new JsonArray(user),
                    }),
                },
                ["streamSettings"] = stream,
            }),
        };
        return root.ToJsonString(Compact);
    }

    /// <summary>Блок контейнера amnezia-xray для ключа vpn:// (поля как в XrayServerConfig::toJson).</summary>
    public static JsonObject BuildAmneziaContainer(string host, XrayEndpoint ep, string clientId)
    {
        var xray = new JsonObject
        {
            ["port"] = ep.Port.ToString(),
            ["transport_proto"] = "tcp",
            ["site"] = ep.Sni,
            ["xray_settings_version"] = 2,
            ["xray_security"] = "reality",
            ["xray_sni"] = ep.Sni,
            ["xray_fingerprint"] = ep.Fingerprint,
            ["xray_transport"] = ep.Transport,
        };
        if (!string.IsNullOrEmpty(ep.Flow)) xray["xray_flow"] = ep.Flow;
        if (ep.Transport == "xhttp")
        {
            xray["xhttp"] = new JsonObject
            {
                ["xhttp_mode"] = "Auto",
                ["xhttp_host"] = string.IsNullOrEmpty(ep.XhttpHost) ? ep.Sni : ep.XhttpHost,
                ["xhttp_path"] = ep.XhttpPath,
                ["xhttp_disable_grpc"] = false,
                ["xhttp_disable_sse"] = false,
                ["xmux"] = new JsonObject { ["xmux_enabled"] = false },
                ["xPadding"] = new JsonObject { ["xpadding_obfs_mode"] = false },
            };
        }
        xray["last_config"] = BuildClientJson(host, ep, clientId);

        return new JsonObject
        {
            ["xray"] = xray,
            ["container"] = "amnezia-xray",
        };
    }

    /// <summary>Ссылка vless:// для сторонних клиентов (v2RayTun, Happ, Streisand, Hiddify…).</summary>
    public static string BuildVlessLink(string host, XrayEndpoint ep, string clientId, string name)
    {
        var q = new List<string>
        {
            "encryption=none",
            "security=reality",
            "sni=" + Uri.EscapeDataString(ep.Sni),
            "fp=" + ep.Fingerprint,
            "pbk=" + Uri.EscapeDataString(ep.PublicKey),
            "sid=" + ep.ShortId,
        };
        if (ep.Transport == "xhttp")
        {
            q.Add("type=xhttp");
            q.Add("host=" + Uri.EscapeDataString(string.IsNullOrEmpty(ep.XhttpHost) ? ep.Sni : ep.XhttpHost));
            q.Add("path=" + Uri.EscapeDataString(ep.XhttpPath));
            q.Add("mode=" + (ep.XhttpMode == "" ? "auto" : ep.XhttpMode));
        }
        else
        {
            q.Add("type=tcp");
            if (!string.IsNullOrEmpty(ep.Flow)) q.Add("flow=" + ep.Flow);
        }
        var h = host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;
        return $"vless://{clientId}@{h}:{ep.Port}?{string.Join("&", q)}#{Uri.EscapeDataString(name)}";
    }

    /// <summary>Случайный путь XHTTP, похожий на обычный API.</summary>
    public static string RandomPath()
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        var rnd = new char[10];
        for (int i = 0; i < rnd.Length; i++) rnd[i] = chars[System.Security.Cryptography.RandomNumberGenerator.GetInt32(chars.Length)];
        return "/" + new string(rnd);
    }
}
