using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Endpoints;
using Mayak.Api.Services;
using Mayak.Core.Crypto;
using Mayak.Core.Export;
using Mayak.Core.Gateway;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Gateway;

/// <summary>Закрытый ключ шлюза. Открытый вшивается в приложение Маяк при сборке (PROD_AGW_PUBLIC_KEY).</summary>
public sealed class GatewayKeys
{
    public RSA? Rsa { get; }
    public string? PublicPem { get; }
    public string Path { get; }

    public GatewayKeys(string path)
    {
        Path = path;
        if (!File.Exists(path)) return;
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        Rsa = rsa;
        PublicPem = rsa.ExportSubjectPublicKeyInfoPem();
    }
}

/// <summary>
/// Шлюз для приложения Маяк — тот же протокол, что у шлюза Amnezia (libagw): приложение на основе
/// AmneziaVPN работает с нами без изменений логики, меняются только адрес шлюза и открытый ключ.
/// Ошибки отдаются как зашифрованный JSON с http_status и message — так их понимает клиент.
/// </summary>
public static class GatewayEndpoints
{
    public const string Prefix = "/gw/";
    public const string ServiceType = "amnezia-premium";
    private static readonly TimeSpan ConfigLifetime = TimeSpan.FromDays(30);

    public static void Map(WebApplication app)
    {
        // Открытый ключ шлюза: его вшивает в приложение сборка (он не секретный).
        app.MapGet(Prefix + "public-key", (GatewayKeys keys) =>
            keys.PublicPem == null ? Results.NotFound() : Results.Text(keys.PublicPem + "\n", "application/x-pem-file"));

        app.MapPost(Prefix + "v1/{method}", async (string method, HttpContext http, GatewayKeys keys, MayakDb db, ClusterService cluster, ILogger<GatewayKeys> log) =>
        {
            if (keys.Rsa == null) return Results.Json(new { error = "Шлюз не настроен" }, statusCode: 503);
            string body;
            using (var reader = new StreamReader(http.Request.Body, Encoding.UTF8))
                body = await reader.ReadToEndAsync();
            string json;
            GatewayCrypto.Session session;
            try
            {
                (json, session) = GatewayCrypto.OpenRequest(body, keys.Rsa);
            }
            catch (GatewayCryptoException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }

            JsonObject result;
            try
            {
                var req = JsonNode.Parse(json) as JsonObject ?? new JsonObject();
                result = method switch
                {
                    "config" => await ConfigAsync(req, db, cluster, http.RequestAborted),
                    "account_info" => await AccountInfoAsync(req, db, cluster, http.RequestAborted),
                    "revoke_config" => await RevokeAsync(req, db, cluster, http.RequestAborted),
                    "news" => new JsonObject { ["news"] = new JsonArray() },
                    "services" => new JsonObject { ["services"] = new JsonArray() },
                    "app_update" => new JsonObject { ["update_available"] = false },
                    _ => Error(404, "Not implemented"),
                };
            }
            catch (JsonException)
            {
                result = Error(400, "Bad payload");
            }
            catch (InvalidOperationException ex)
            {
                log.LogWarning("Шлюз {Method}: {Error}", method, ex.Message);
                result = Error(503, ex.Message);
            }
            return Results.Bytes(GatewayCrypto.SealResponse(result.ToJsonString(), session), "application/octet-stream");
        });
    }

    private static JsonObject Error(int status, string message) => new() { ["http_status"] = status, ["message"] = message };

    private static string? Str(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : null;

    private static async Task<(Account? Account, JsonObject? Error)> AuthAsync(JsonObject req, MayakDb db, CancellationToken ct)
    {
        var key = (req["auth_data"] as JsonObject) is { } auth ? Str(auth, "api_key") : null;
        if (key == null) return (null, Error(404, "Account not found."));
        var acc = await db.Accounts.FirstOrDefaultAsync(a => a.AppKey == key, ct);
        if (acc == null) return (null, Error(404, "Account not found."));
        if (!acc.Enabled) return (acc, Error(402, "Access is not approved yet"));
        if (!acc.IsActive(DateTime.UtcNow)) return (acc, Error(402, "Subscription expired"));
        return (acc, null);
    }

    private static DeviceKind KindOf(string? os) => (os ?? "").ToLowerInvariant() switch
    {
        var s when s.Contains("ios") => DeviceKind.IPhone,
        var s when s.Contains("android") => DeviceKind.Android,
        var s when s.Contains("windows") => DeviceKind.Windows,
        var s when s.Contains("mac") || s.Contains("osx") => DeviceKind.Mac,
        var s when s.Length > 0 => DeviceKind.Linux,
        _ => DeviceKind.Other,
    };

    /// <summary>v1/config: устройство приложения регистрирует свой открытый ключ и получает настройки.</summary>
    private static async Task<JsonObject> ConfigAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (acc, err) = await AuthAsync(req, db, ct);
        if (err != null) return err;
        var protocol = Str(req, "service_protocol") ?? "awg";
        if (protocol != "awg") return Error(404, "No active configuration found for this protocol");
        var pub = Str(req, "public_key");
        if (pub == null || !IsWgKey(pub)) return Error(400, "public_key is required");
        var install = Str(req, "installation_uuid") ?? "";
        var c = await cluster.GetAsync(ct) ?? throw new InvalidOperationException("Нет ни одного выхода");

        var device = install.Length == 0 ? null : await db.Devices.FirstOrDefaultAsync(d => d.AccountId == acc!.Id && d.InstallationId == install, ct);
        var other = await db.Devices.FirstOrDefaultAsync(d => d.AwgPublicKey == pub, ct);
        if (other != null && other.Id != device?.Id) return Error(409, "This key is already in use");
        if (device == null)
        {
            var count = await db.Devices.CountAsync(d => d.AccountId == acc!.Id, ct);
            if (count >= acc!.MaxDevices) return Error(409, $"Device limit reached ({acc.MaxDevices})");
            var kind = KindOf(Str(req, "os_version"));
            device = new Device
            {
                AccountId = acc.Id,
                Name = AppEndpoints.KindName(kind),
                Kind = kind,
                Ip = await cluster.AllocateIpAsync(c, null, ct),
                XrayId = Guid.NewGuid().ToString(),
                InstallationId = install.Length > 0 ? install : null,
            };
            db.Devices.Add(device);
        }
        // Приложение создаёт новую пару ключей при каждом обновлении настроек: старый ключ сразу отзываем.
        device.AwgPublicKey = pub;
        device.AwgPrivateKey = null;
        device.OsVersion = Str(req, "os_version");
        device.AppVersion = Str(req, "app_version");
        device.ConfigFetchedAt = DateTime.UtcNow;
        db.Audit.Add(new AuditEntry { ActorId = acc!.Id, Action = "app.config", Details = $"{device.Name} {device.OsVersion} {device.AppVersion}" });
        await db.SaveChangesAsync(ct);
        await cluster.BumpAsync(ct);

        var config = await BuildConfigAsync(acc, device, c, cluster, ct);
        return new JsonObject
        {
            ["config"] = VpnKeyCodec.Encode(config.ToJsonString()),
            ["service_info"] = new JsonObject { ["is_ad_visible"] = false, ["is_renewal_available"] = false },
        };
    }

    private static bool IsWgKey(string s)
    {
        try { return Convert.FromBase64String(s).Length == 32; }
        catch (FormatException) { return false; }
    }

    private static async Task<JsonObject> BuildConfigAsync(Account acc, Device d, ClusterIdentity c, ClusterService cluster, CancellationToken ct)
    {
        var ep = ClusterService.AwgOf(c);
        ep.Host = await cluster.PublicHostAsync(c, ct);
        var vd = new VpnDevice { Id = d.Id, Name = d.Name, Kind = d.Kind, PrivateKey = "$WIREGUARD_CLIENT_PRIVATE_KEY", PublicKey = d.AwgPublicKey, Ip = d.Ip, XrayId = d.XrayId };
        var root = JsonNode.Parse(ClientConfigFactory.BuildAmneziaJson(ep, vd, c.Dns1, c.Dns2, c.Title))!.AsObject();
        var loc = await LocationAsync(cluster, ct);
        root["config_version"] = 2;
        root["name"] = c.Title;
        root["api_config"] = ApiConfig(acc, loc);
        root["auth_data"] = new JsonObject { ["api_key"] = acc.AppKey };
        return root;
    }

    private static async Task<(string Code, string Name)> LocationAsync(ClusterService cluster, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToNode(await cluster.LocationAsync(ct)) as JsonObject;
        var code = json?["CountryCode"]?.GetValue<string>() is { Length: > 0 } cc ? cc : "fi";
        var name = json?["City"]?.GetValue<string>() is { Length: > 0 } city ? city : json?["Country"]?.GetValue<string>() ?? "Маяк";
        return (code, name);
    }

    private static JsonObject ApiConfig(Account acc, (string Code, string Name) loc) => new()
    {
        ["service_type"] = ServiceType,
        ["service_protocol"] = "awg",
        ["user_country_code"] = "ru",
        ["server_country_code"] = loc.Code,
        ["server_country_name"] = loc.Name,
        ["available_countries"] = new JsonArray(new JsonObject
        {
            ["server_country_code"] = loc.Code,
            ["server_country_name"] = loc.Name,
            ["available_protocols"] = new JsonArray("awg"),
        }),
        ["subscription"] = new JsonObject { ["end_date"] = acc.PaidUntil?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? "" },
        // Через месяц (или по окончании оплаты) приложение само обновит настройки.
        ["public_key"] = new JsonObject { ["expires_at"] = Min(acc.PaidUntil, DateTime.UtcNow + ConfigLifetime).ToString("yyyy-MM-ddTHH:mm:ssZ") },
    };

    private static DateTime Min(DateTime? a, DateTime b) => a is DateTime x && x < b ? x : b;

    private static async Task<JsonObject> AccountInfoAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (acc, err) = await AuthAsync(req, db, ct);
        if (err != null && acc == null) return err;
        var devices = await db.Devices.Where(d => d.AccountId == acc!.Id).OrderBy(d => d.CreatedAt).ToListAsync(ct);
        var loc = await LocationAsync(cluster, ct);
        var issued = new JsonArray();
        foreach (var d in devices.Where(d => d.InstallationId != null))
        {
            var at = (d.ConfigFetchedAt ?? d.CreatedAt).ToString("ddd MMM d HH:mm:ss yyyy", System.Globalization.CultureInfo.InvariantCulture);
            issued.Add(new JsonObject
            {
                ["source_type"] = "gateway_account",
                ["installation_uuid"] = d.InstallationId,
                ["os_version"] = d.OsVersion ?? d.Name,
                ["server_country_code"] = loc.Code,
                ["server_country_name"] = loc.Name,
                ["last_downloaded"] = at,
                ["worker_last_updated"] = at,
            });
        }
        return new JsonObject
        {
            ["active_device_count"] = devices.Count,
            ["max_device_count"] = acc!.MaxDevices,
            ["subscription_end_date"] = acc.PaidUntil?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? "",
            ["subscription_description"] = acc.PaidUntil == null ? "Без срока" : $"До {acc.PaidUntil:dd.MM.yyyy}",
            ["is_renewal_available"] = false,
            ["available_countries"] = ApiConfig(acc, loc)["available_countries"]!.DeepClone(),
            ["issued_configs"] = issued,
        };
    }

    /// <summary>v1/revoke_config: приложение отключает своё устройство (или другое из списка устройств).</summary>
    private static async Task<JsonObject> RevokeAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (acc, err) = await AuthAsync(req, db, ct);
        if (acc == null) return err!;
        var install = Str(req, "installation_uuid");
        var d = install == null ? null : await db.Devices.FirstOrDefaultAsync(x => x.AccountId == acc.Id && x.InstallationId == install, ct);
        if (d == null) return Error(404, "No active configuration found for this device");
        db.Devices.Remove(d);
        db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "app.revoke", Details = d.Name });
        await db.SaveChangesAsync(ct);
        await cluster.BumpAsync(ct);
        return new JsonObject { ["ok"] = true };
    }

    /// <summary>Ключ подписки vpn:// для приложения Маяк: устройств в нём нет — приложение получит настройки само.</summary>
    public static string SubscriptionKey(Account acc, string title) =>
        VpnKeyCodec.Encode(new JsonObject
        {
            ["config_version"] = 2,
            ["name"] = title,
            ["description"] = title,
            ["api_config"] = new JsonObject
            {
                ["service_type"] = ServiceType,
                ["service_protocol"] = "awg",
                ["user_country_code"] = "ru",
            },
            ["auth_data"] = new JsonObject { ["api_key"] = acc.AppKey },
        }.ToJsonString());
}
