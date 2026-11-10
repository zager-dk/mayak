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

        app.MapPost(Prefix + "v1/{method}", async (string method, HttpContext http, GatewayKeys keys, MayakDb db, ClusterService cluster, ILogger<GatewayKeys> log, IConfiguration cfg) =>
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
                    "config" => await ConfigAsync(req, db, cluster, http.RequestAborted, cfg),
                    "admission" => await AdmissionAsync(req, db, cluster, http.RequestAborted),
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
            catch (DbUpdateConcurrencyException)
            {
                // Устройство удалено параллельной заменой или отключением: отвечаем зашифрованной ошибкой, а не HTTP 500.
                result = Error(409, "Device changed concurrently, retry");
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
    private static JsonObject AdmissionError(int status, string code, string message, int? retry = null)
    {
        var result = Error(status, message);
        result["code"] = code;
        if (retry is int ms) result["retry_after_ms"] = ms;
        return result;
    }

    private static string? Str(JsonObject o, string key) => o[key] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : null;

    /// <summary>
    /// Ключ из auth_data: либо ключ аккаунта (старые установки), либо токен устройства md1.… — тогда Bound указывает
    /// единственное устройство, от имени которого можно действовать. Stale — ключ уже сменён (предыдущий токен или
    /// ключ, которым открыта попытка): им можно только завершить старую попытку (release/reconcile).
    /// </summary>
    private static async Task<(Account? Account, Device? Bound, bool Stale, JsonObject? Error)> AuthAsync(JsonObject req, MayakDb db, CancellationToken ct)
    {
        var key = (req["auth_data"] as JsonObject) is { } auth ? Str(auth, "api_key") : null;
        if (key == null) return (null, null, false, Error(404, "Account not found."));
        Account? acc;
        Device? bound = null;
        bool stale = false;
        if (DeviceAccess.IsDeviceToken(key))
        {
            var hash = Tokens.Hash(key);
            bound = await db.Devices.Include(d => d.Account).FirstOrDefaultAsync(d => d.AppTokenHash == hash, ct);
            if (bound == null)
            {
                bound = await db.Devices.Include(d => d.Account).FirstOrDefaultAsync(d => d.PreviousAppTokenHash == hash, ct)
                        ?? await db.Devices.Include(d => d.Account)
                            .FirstOrDefaultAsync(d => db.AwgAllocations.Any(a => a.DeviceId == d.Id && a.AuthKeyHash == hash), ct);
                stale = bound != null;
            }
            acc = bound?.Account;
            if (acc == null) return (null, null, false, Error(404, "Account not found."));
        }
        else
        {
            acc = await db.Accounts.FirstOrDefaultAsync(a => a.AppKey == key, ct);
            if (acc == null) return (null, null, false, Error(404, "Account not found."));
        }
        if (!acc.Enabled) return (acc, bound, stale, Error(402, "Access is not approved yet"));
        if (!acc.IsActive(DateTime.UtcNow)) return (acc, bound, stale, Error(402, "Subscription expired"));
        return (acc, bound, stale, null);
    }

    /// <summary>v1/config: устройство приложения регистрирует свой открытый ключ и получает настройки.</summary>
    private static async Task<JsonObject> ConfigAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct, IConfiguration cfg)
    {
        var suppliedKey = req["auth_data"] is JsonObject suppliedAuth ? Str(suppliedAuth, "api_key") : null;
        var (acc, bound, stale, err) = await AuthAsync(req, db, ct);
        if (err != null) return err;
        if (stale) return Error(404, "Account not found.");
        var protocol = Str(req, "service_protocol") ?? "awg";
        if (protocol is not ("awg" or "vless")) return Error(404, "No active configuration found for this protocol");
        if (protocol == "vless" && !cfg.GetValue("VlessPool:Enabled", false)) return Error(404, "No active configuration found for this protocol");
        var pub = Str(req, "public_key");
        if (protocol == "awg" && (pub == null || !IsWgKey(pub))) return Error(400, "public_key is required");
        var install = Str(req, "installation_uuid") ?? "";
        bool autoConnectRequested = req["mayak_auto_connect"] is JsonValue autoValue && autoValue.TryGetValue<int>(out var autoConnect) && autoConnect == 1;
        if (autoConnectRequested && protocol != "awg") return AdmissionError(400, "INVALID_REQUEST", "auto-connect supports AWG only");
        if (autoConnectRequested && install.Length == 0) return AdmissionError(400, "INVALID_REQUEST", "installation_uuid is required for auto-connect");
        if (protocol == "vless" && install.Length == 0) return Error(400, "installation_uuid is required for VLESS");
        var c = await cluster.GetAsync(ct) ?? throw new InvalidOperationException("Нет ни одного выхода");

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DeviceWriteLock.AcquireAsync(db, ct);
        await db.Entry(c).ReloadAsync(ct);
        await db.Entry(acc!).ReloadAsync(ct);
        if (!acc!.IsActive(DateTime.UtcNow)) return Error(402, "Access is not active");
        Device? device;
        if (bound != null)
        {
            // Токен устройства: только своё устройство и своя установка; нового устройства по нему не бывает.
            await db.Entry(bound).ReloadAsync(ct);
            if (db.Entry(bound).State == EntityState.Detached || !DeviceAccess.KeyAuthorizes(acc, bound, suppliedKey))
                return Error(404, "Account not found.");
            if (install.Length == 0 || bound.InstallationId != install) return Error(403, "This device key belongs to another installation");
            device = bound;
        }
        else
        {
            if (suppliedKey == null || !string.Equals(acc.AppKey, suppliedKey, StringComparison.Ordinal))
                return Error(404, "Account not found.");
            device = install.Length == 0 ? null : await db.Devices.FirstOrDefaultAsync(d => d.AccountId == acc.Id && d.InstallationId == install, ct);
            // Установка уже перешла на свой токен: ключ аккаунта её больше не представляет.
            if (device is { AppTokenHash: not null }) return Error(403, "This installation uses its own device key");
            if (device == null && !cfg.GetValue("Devices:LegacyKeyCreatesDevices", true))
                return Error(403, "Sign in to the Mayak app to add this device");
        }
        if (device is { Enabled: false }) return Error(402, "Device is disabled");
        var other = protocol != "awg" || pub == null ? null : await db.Devices.FirstOrDefaultAsync(d => d.AwgPublicKey == pub, ct);
        if (other != null && other.Id != device?.Id) return Error(409, "This key is already in use");
        if (device != null && protocol == "vless" && device.ServiceProtocol != "vless") return Error(409, "VLESS requires a new pool device");
        if (device?.ServiceProtocol == "vless" && protocol != "vless") return Error(409, "Pool device requires VLESS");
        if (device == null)
        {
            try { await DeviceWriteLock.EnsureRoomAsync(db, acc!, ct); }
            catch (DeviceLimitException) { return Error(409, $"Device limit reached ({acc!.MaxDevices})"); }
            var kind = DeviceAccess.KindOf(Str(req, "os_version"));
            device = new Device
            {
                AccountId = acc!.Id,
                Name = AppEndpoints.KindName(kind),
                Kind = kind,
                Ip = await cluster.AllocateIpAsync(c, null, ct),
                XrayId = Guid.NewGuid().ToString(),
                InstallationId = install.Length > 0 ? install : null,
            };
            if (protocol == "vless")
            {
                var (_, internalPublic) = Curve25519.GenerateKeyPair();
                device.AwgPublicKey = internalPublic;
                device.AwgPrivateKey = null; // API keeps no private key for app-owned devices.
                device.ServiceProtocol = "vless";
            }
            db.Devices.Add(device);
        }
        // Only a real peer identity change alters cluster state and needs an agent acknowledgement.
        bool peerChanged = protocol == "awg" && !string.Equals(device.AwgPublicKey, pub, StringComparison.Ordinal);
        if (peerChanged) { device.AwgPublicKey = pub!; device.AwgPrivateKey = null; }
        if (autoConnectRequested) device.AutoConnectManaged = true;
        device.OsVersion = Str(req, "os_version");
        device.AppVersion = Str(req, "app_version");
        device.ConfigFetchedAt = DateTime.UtcNow;
        if (peerChanged) c.Revision++;
        db.Audit.Add(new AuditEntry { ActorId = acc!.Id, Action = "app.config", Details = $"{device.Name} {device.OsVersion} {device.AppVersion}" });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        if (peerChanged) cluster.SignalRevisionChanged();

        if (protocol == "vless")
        {
            await using var poolTx = await db.Database.BeginTransactionAsync(ct);
            await DeviceWriteLock.AcquireAsync(db, ct);
            await db.Entry(acc!).ReloadAsync(ct);
            await db.Entry(device).ReloadAsync(ct);
            if (db.Entry(device).State == EntityState.Detached) return Error(404, "No active configuration found for this device");
            if (!acc!.IsActive(DateTime.UtcNow) || !device.Enabled) return Error(402, "Access is not active");
            if (!DeviceAccess.KeyAuthorizes(acc, device, suppliedKey)) return Error(404, "Account not found.");
            bool wasUnassigned = device.ExitEndpointId == null;
            var selected = await cluster.AssignPoolEndpointAsync(device, ct);
            if (selected == null) { await poolTx.CommitAsync(ct); return Error(503, device.ExitEndpointId == null ? "no_ready_exit" : "provisioning"); }
            if (!ClusterService.IsPoolReady(selected, DateTime.UtcNow)) { await poolTx.CommitAsync(ct); return Error(503, "provisioning"); }
            var result = new JsonObject { ["config"] = VpnKeyCodec.Encode(PoolGatewayConfig(acc!, device, selected, suppliedKey!).ToJsonString()),
                ["service_info"] = new JsonObject { ["is_ad_visible"] = false, ["is_renewal_available"] = false } };
            await poolTx.CommitAsync(ct);
            if (wasUnassigned) await cluster.BumpAsync(ct);
            return result;
        }

        var config = await BuildConfigAsync(acc, device, c, cluster, suppliedKey!, ct);
        if (autoConnectRequested)
        {
            var current = await cluster.GetAsync(ct);
            if (current == null) return AdmissionError(503, "provisioning", "provisioning", 1500);
            var candidates = await new AwgAdmissionService(db).CandidatesAsync(device, current, ct);
            if (candidates.Count == 0)
            {
                var awaitingAck = await db.Servers.AnyAsync(s => s.Role == ServerRoles.Exit && s.AutoSelectEnabled &&
                    s.ProvisioningStatus == "installed" && s.ProvisioningConfirmedRevision != current.Revision, ct);
                return awaitingAck
                    ? AdmissionError(503, "provisioning", "provisioning", 1500)
                    : AdmissionError(503, "no_ready_exit", "no_ready_exit");
            }
            var ips = new JsonArray();
            foreach (var candidate in candidates)
            {
                var expected = new JsonArray();
                foreach (var ip in candidate.ExpectedEgressIps) expected.Add(ip);
                ips.Add(new JsonObject { ["id"] = candidate.Id.ToString(), ["host"] = candidate.Host, ["port"] = candidate.Port,
                    ["preferred"] = candidate.Preferred, ["expected_egress_ips"] = expected });
            }
            var expiry = Min(acc!.PaidUntil, DateTime.UtcNow + ConfigLifetime);
            return new JsonObject
            {
                ["config"] = VpnKeyCodec.Encode(config.ToJsonString()),
                ["service_info"] = new JsonObject { ["is_ad_visible"] = false, ["is_renewal_available"] = false },
                ["mayak_connection"] = new JsonObject { ["schema"] = 1, ["revision"] = current.Revision,
                    ["expires_at"] = expiry.ToString("yyyy-MM-ddTHH:mm:ssZ"), ["candidates"] = ips }
            };
        }
        return new JsonObject
        {
            ["config"] = VpnKeyCodec.Encode(config.ToJsonString()),
            ["service_info"] = new JsonObject { ["is_ad_visible"] = false, ["is_renewal_available"] = false },
        };
    }

    private static async Task<JsonObject> AdmissionAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (account, bound, stale, authError) = await AuthAsync(req, db, ct);
        if (authError != null)
        {
            var authCode = account == null ? "INVALID_REQUEST" : !account.Enabled ? "DISABLED" : "ACCOUNT_EXPIRED";
            authError["code"] = authCode;
            return authError;
        }
        var install = Str(req, "installation_uuid");
        var publicKey = Str(req, "public_key");
        var action = Str(req, "action");
        var attempt = Str(req, "attempt_id");
        var expectedAppKey = Str(req["auth_data"] as JsonObject ?? new JsonObject(), "api_key");
        if (install == null || publicKey == null || action is not ("acquire" or "proven" or "release" or "reconcile") ||
            attempt == null || expectedAppKey == null || !AwgAdmissionService.IsValidAttemptId(attempt))
            return AdmissionError(400, "INVALID_REQUEST", "Invalid admission request");
        var device = await db.Devices.FirstOrDefaultAsync(d => d.AccountId == account!.Id && d.InstallationId == install && d.AwgPublicKey == publicKey, ct);
        if (device == null || bound != null && device.Id != bound.Id) return AdmissionError(404, "INVALID_REQUEST", "Device not found");
        if (stale && action is not ("release" or "reconcile")) return AdmissionError(403, "REVOKED", "REVOKED");
        if (action == "reconcile")
        {
            var authorized = await new AwgAdmissionService(db).ReconcileAsync(account!, device, expectedAppKey, install, publicKey, attempt, ct);
            if (!authorized) return AdmissionError(403, "REVOKED", "REVOKED");
            return new JsonObject { ["reconciled"] = true };
        }
        if (action is "proven" or "release")
        {
            if (!Guid.TryParse(Str(req, "allocation_id"), out var id)) return AdmissionError(400, "INVALID_REQUEST", "allocation_id is required");
            var (authorized, updated) = await new AwgAdmissionService(db).SetAllocationAsync(account!, device, expectedAppKey,
                install, publicKey, id, attempt, action, ct);
            if (!authorized) return AdmissionError(403, "REVOKED", "REVOKED");
            return new JsonObject { [action == "proven" ? "proven" : "released"] = updated };
        }
        if (!Guid.TryParse(Str(req, "candidate_id"), out var candidateId)) return AdmissionError(400, "INVALID_REQUEST", "candidate_id is required");
        var current = await cluster.GetAsync(ct);
        if (current == null) return AdmissionError(503, "NOT_READY", "no_ready_exit", 1500);
        var service = new AwgAdmissionService(db);
        var (code, allocation, host) = await service.AcquireAsync(account!, device, expectedAppKey, install, publicKey,
            candidateId, attempt, current, ct);
        if (code != null)
        {
            if (code == "NOT_READY")
            {
                var server = await db.Servers.AsNoTracking().FirstOrDefaultAsync(s => s.Id == candidateId, ct);
                if (server != null && !server.AutoSelectEnabled) code = "DISABLED";
            }
            var status = code switch { "FULL" => 503, "ACCOUNT_EXPIRED" => 402, "REVOKED" or "DISABLED" => 403, "INVALID_REQUEST" => 400, _ => 503 };
            return AdmissionError(status, code, code, code == "NOT_READY" ? 1500 : null);
        }
        var endpoint = ClusterService.AwgOf(current);
        endpoint.Host = host!;
        var client = new VpnDevice { Id = device.Id, Name = device.Name, Kind = device.Kind, PrivateKey = "$WIREGUARD_CLIENT_PRIVATE_KEY",
            PublicKey = device.AwgPublicKey, Ip = device.Ip, XrayId = device.XrayId };
        var payload = JsonNode.Parse(ClientConfigFactory.BuildAmneziaJson(endpoint, client, current.Dns1, current.Dns2, current.Title))!.AsObject();
        payload["config_version"] = 2;
        payload["name"] = current.Title;
        payload["api_config"] = ApiConfig(account!, await LocationAsync(cluster, ct));
        payload["auth_data"] = new JsonObject { ["api_key"] = expectedAppKey };
        var response = new JsonObject { ["allocation_id"] = allocation!.Id.ToString(), ["connect_before"] = allocation.CreatedAt.AddSeconds(30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["config_revision"] = current.Revision, ["config"] = VpnKeyCodec.Encode(payload.ToJsonString()) };
        if (ExitLocationCatalog.IsRequested(req))
        {
            // Acquire returns the authoritative exit for both fresh and idempotent attempts.
            var selectedExit = await db.Servers.AsNoTracking()
                .Where(s => s.Id == allocation.ServerId)
                .Select(s => new { s.City, s.Country, s.CountryCode })
                .FirstOrDefaultAsync(ct);
            ExitLocationCatalog.AddToResponse(response, req, allocation.ServerId,
                selectedExit?.City, selectedExit?.Country, selectedExit?.CountryCode);
        }
        if (XrayPathCatalog.IsRequested(req) && XrayPathCatalog.Build(current, host!, device) is { } xrayPaths)
            response["xray_paths"] = xrayPaths;
        return response;
    }

    private static bool IsWgKey(string s)
    {
        try { return Convert.FromBase64String(s).Length == 32; }
        catch (FormatException) { return false; }
    }

    /// <param name="apiKey">Ключ, которым пришёл запрос: ответ возвращает его же, чтобы устройство с токеном не получило ключ аккаунта.</param>
    private static async Task<JsonObject> BuildConfigAsync(Account acc, Device d, ClusterIdentity c, ClusterService cluster, string apiKey, CancellationToken ct)
    {
        var ep = ClusterService.AwgOf(c);
        ep.Host = await cluster.PublicHostAsync(c, ct);
        var vd = new VpnDevice { Id = d.Id, Name = d.Name, Kind = d.Kind, PrivateKey = "$WIREGUARD_CLIENT_PRIVATE_KEY", PublicKey = d.AwgPublicKey, Ip = d.Ip, XrayId = d.XrayId };
        var root = JsonNode.Parse(ClientConfigFactory.BuildAmneziaJson(ep, vd, c.Dns1, c.Dns2, c.Title))!.AsObject();
        var loc = await LocationAsync(cluster, ct);
        root["config_version"] = 2;
        root["name"] = c.Title;
        root["api_config"] = ApiConfig(acc, loc);
        root["auth_data"] = new JsonObject { ["api_key"] = apiKey };
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

    public static string BuildPoolLink(ExitEndpoint endpoint, Device device)
    {
        var query = new List<string> { "encryption=none", "security=reality", "sni=" + Uri.EscapeDataString(endpoint.Sni),
            "fp=" + Uri.EscapeDataString(endpoint.Fingerprint), "pbk=" + Uri.EscapeDataString(endpoint.PublicKey), "sid=" + Uri.EscapeDataString(endpoint.ShortId) };
        if (endpoint.Transport == "xhttp")
        {
            query.Add("type=xhttp");
            query.Add("host=" + Uri.EscapeDataString(string.IsNullOrEmpty(endpoint.XhttpHost) ? endpoint.Sni : endpoint.XhttpHost));
            query.Add("path=" + Uri.EscapeDataString(endpoint.XhttpPath));
            query.Add("mode=" + Uri.EscapeDataString(string.IsNullOrEmpty(endpoint.XhttpMode) ? "auto" : endpoint.XhttpMode));
        }
        else
        {
            query.Add("type=tcp");
            if (!string.IsNullOrEmpty(endpoint.Flow)) query.Add("flow=" + Uri.EscapeDataString(endpoint.Flow));
        }
        var host = endpoint.Host.Contains(':') && !endpoint.Host.StartsWith('[') ? $"[{endpoint.Host}]" : endpoint.Host;
        return $"vless://{Uri.EscapeDataString(device.XrayId)}@{host}:{endpoint.Port}?{string.Join('&', query)}#{Uri.EscapeDataString(device.Name)}";
    }

    public static XrayEndpoint PoolXrayOf(ExitEndpoint endpoint) => new()
    {
        Port = endpoint.Port, PublicKey = endpoint.PublicKey, Sni = endpoint.Sni, ShortId = endpoint.ShortId,
        Transport = endpoint.Transport == "xhttp" ? "xhttp" : "raw", Flow = endpoint.Transport == "xhttp" ? "" : endpoint.Flow,
        Fingerprint = endpoint.Fingerprint, XhttpHost = endpoint.XhttpHost, XhttpPath = endpoint.XhttpPath, XhttpMode = endpoint.XhttpMode,
    };

    /// <summary>Existing native ContainerConfig format, using only the assigned endpoint and device UUID.</summary>
    public static JsonObject PoolClientConfig(Device device, ExitEndpoint endpoint)
    {
        var xray = PoolXrayOf(endpoint);
        var container = Mayak.Core.Xray.XrayConfig.BuildAmneziaContainer(endpoint.Host, xray, device.XrayId);
        if (endpoint.Transport == "xhttp") container["xray"]!["xhttp"]!["xhttp_mode"] = endpoint.XhttpMode;
        return new JsonObject
        {
            ["config_version"] = 2, ["name"] = device.Name, ["hostName"] = endpoint.Host,
            ["defaultContainer"] = "amnezia-xray", ["containers"] = new JsonArray(container),
            ["dns1"] = "1.1.1.1", ["dns2"] = "1.0.0.1",
        };
    }

    private static JsonObject PoolGatewayConfig(Account acc, Device device, ExitEndpoint endpoint, string apiKey)
    {
        var root = PoolClientConfig(device, endpoint);
        root["api_config"] = new JsonObject { ["service_type"] = ServiceType, ["service_protocol"] = "vless", ["user_country_code"] = "ru",
            ["available_countries"] = new JsonArray(new JsonObject { ["server_country_code"] = "", ["server_country_name"] = "", ["available_protocols"] = new JsonArray("vless") }),
            ["subscription"] = new JsonObject { ["end_date"] = acc.PaidUntil?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? "" } };
        root["auth_data"] = new JsonObject { ["api_key"] = apiKey };
        return root;
    }

    private static DateTime Min(DateTime? a, DateTime b) => a is DateTime x && x < b ? x : b;

    private static async Task<JsonObject> AccountInfoAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (acc, bound, stale, err) = await AuthAsync(req, db, ct);
        if (err != null && acc == null) return err;
        if (stale) return Error(404, "Account not found.");
        if (bound is { Enabled: false }) return Error(402, "Device is disabled");
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

    /// <summary>
    /// v1/revoke_config: приложение отключает своё устройство (или другое из списка устройств).
    /// С токеном устройства — любое устройство своего аккаунта. С ключом аккаунта — только устройства без своего токена:
    /// утёкший ключ аккаунта не выбивает устройства, вошедшие по почте и паролю.
    /// </summary>
    private static async Task<JsonObject> RevokeAsync(JsonObject req, MayakDb db, ClusterService cluster, CancellationToken ct)
    {
        var (acc, bound, stale, err) = await AuthAsync(req, db, ct);
        if (acc == null) return err!;
        if (stale) return Error(404, "Account not found.");
        var key = Str(req["auth_data"] as JsonObject ?? new JsonObject(), "api_key");
        var install = Str(req, "installation_uuid");
        if (install == null) return Error(404, "No active configuration found for this device");
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DeviceWriteLock.AcquireAsync(db, ct);
        await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, ct);
        // Ключ и устройство проверяются заново под блокировкой: параллельная выдача ключа или замена могли их изменить.
        await db.Entry(acc).ReloadAsync(ct);
        if (bound != null)
        {
            await db.Entry(bound).ReloadAsync(ct);
            if (db.Entry(bound).State == EntityState.Detached || !DeviceAccess.KeyAuthorizes(acc, bound, key))
                return Error(404, "Account not found.");
            if (!bound.Enabled) return Error(402, "Device is disabled");
        }
        else if (!string.Equals(acc.AppKey, key, StringComparison.Ordinal)) return Error(404, "Account not found.");
        var d = await db.Devices.FirstOrDefaultAsync(x => x.AccountId == acc.Id && x.InstallationId == install, ct);
        if (d == null) return Error(404, "No active configuration found for this device");
        if (bound == null && d.AppTokenHash != null) return Error(403, "This device can be removed only from a signed-in device");
        db.Devices.Remove(d);
        db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "app.revoke", Details = d.Name });
        await db.SaveChangesAsync(ct);
        await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, ct);
        await tx.CommitAsync(ct);
        await cluster.BumpAsync(ct);
        return new JsonObject { ["ok"] = true };
    }

    /// <summary>Ключ подписки vpn:// для приложения Маяк: устройств в нём нет — приложение получит настройки само.</summary>
    public static string SubscriptionKey(Account acc, string title, string protocol = "awg") => SubscriptionKey(acc.AppKey!, title, protocol);

    /// <summary>То же для ключа устройства (md1.…) или ключа аккаунта.</summary>
    public static string SubscriptionKey(string apiKey, string title, string protocol = "awg") =>
        VpnKeyCodec.Encode(new JsonObject
        {
            ["config_version"] = 2,
            ["name"] = title,
            ["description"] = title,
            ["api_config"] = new JsonObject
            {
                ["service_type"] = ServiceType,
                ["service_protocol"] = protocol,
                ["user_country_code"] = "ru",
            },
            ["auth_data"] = new JsonObject { ["api_key"] = apiKey },
        }.ToJsonString());
}
