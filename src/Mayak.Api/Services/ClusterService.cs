using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Core.Agent;
using Mayak.Core.Crypto;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

/// <summary>Общие ключи выходов, выдача адресов в VPN, состояние для агентов.</summary>
public sealed class ClusterService
{
    public static readonly TimeSpan PoolReportFreshness = TimeSpan.FromSeconds(120);
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    private readonly MayakDb _db;

    public ClusterService(MayakDb db) => _db = db;

    public Task<ClusterIdentity?> GetAsync(CancellationToken ct = default) => _db.Cluster.FirstOrDefaultAsync(c => c.Id == 1, ct);

    public static ServerEndpoint AwgOf(ClusterIdentity c) => JsonSerializer.Deserialize<ServerEndpoint>(c.AwgJson, Json) ?? new ServerEndpoint();

    public static XrayEndpoint? XrayOf(ClusterIdentity c) =>
        string.IsNullOrEmpty(c.XrayJson) ? null : JsonSerializer.Deserialize<XrayEndpoint>(c.XrayJson, Json);

    /// <summary>Допустимые отпечатки uTLS для клиентов (значения Xray fingerprint).</summary>
    public static readonly string[] ClientFingerprints = ["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"];

    public static bool IsClientFingerprint(string value) => ClientFingerprints.Contains(value, StringComparer.Ordinal);

    /// <summary>Отпечаток для клиентов, если в админке не выбран другой: chrome в российских сетях глушится (10.11.2026).</summary>
    public const string DefaultClientFingerprint = "firefox";

    public static string EffectiveClientFingerprint(ClusterIdentity c) =>
        c.XrayClientFingerprint is { } fp && IsClientFingerprint(fp) ? fp : DefaultClientFingerprint;

    /// <summary>
    /// Xray кластера для выдачи клиентам: с отпечатком из XrayClientFingerprint (по умолчанию firefox).
    /// Только для ссылок, подписок и конфигов. Identity выхода и агент работают с <see cref="XrayOf"/>.
    /// </summary>
    public static XrayEndpoint? ClientXrayOf(ClusterIdentity c)
    {
        var xray = XrayOf(c);
        if (xray != null) xray.Fingerprint = EffectiveClientFingerprint(c);
        return xray;
    }

    /// <summary>Запоминает ключи первого выхода как общие для всех. Возвращает false, если общие ключи уже есть.</summary>
    public async Task<bool> AdoptIdentityAsync(AgentIdentity id, CancellationToken ct)
    {
        var ownsTransaction = _db.Database.CurrentTransaction == null;
        await using var tx = ownsTransaction ? await _db.Database.BeginTransactionAsync(ct) : null;
        await _db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(742019, 2)", ct);
        if (await GetAsync(ct) != null)
        {
            if (tx != null) await tx.CommitAsync(ct);
            return false;
        }
        var awg = id.Awg;
        awg.Host = "";
        _db.Cluster.Add(new ClusterIdentity
        {
            AwgJson = JsonSerializer.Serialize(awg),
            AwgServerPrivateKey = id.AwgServerPrivateKey,
            XrayJson = id.Xray == null ? null : JsonSerializer.Serialize(id.Xray),
            XrayPrivateKey = id.XrayPrivateKey,
            Dns1 = id.Dns1,
            Dns2 = id.Dns2,
            Title = id.Title,
        });
        await _db.SaveChangesAsync(ct);
        if (tx != null) await tx.CommitAsync(ct);
        return true;
    }

    public async Task<bool> MatchesIdentityAsync(AgentIdentity id, CancellationToken ct)
    {
        var saved = await _db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
        return saved != null && IdentityMatches(saved, id);
    }

    public static bool IdentityMatches(ClusterIdentity saved, AgentIdentity incoming)
    {
        var awg = incoming.Awg;
        awg.Host = "";
        var expectedAwg = AwgOf(saved);
        expectedAwg.Host = "";
        if (JsonSerializer.Serialize(awg, Json) != JsonSerializer.Serialize(expectedAwg, Json) ||
            // DNS и название не сверяем: агент держит свои локальные значения и не получает их из API,
            // поэтому после правки в админке выход не прошёл бы знакомство при следующем перезапуске агента.
            saved.AwgServerPrivateKey != incoming.AwgServerPrivateKey || saved.XrayPrivateKey != incoming.XrayPrivateKey)
            return false;
        var savedXray = XrayOf(saved);
        if (savedXray == null || incoming.Xray == null) return savedXray == null && incoming.Xray == null;
        return JsonSerializer.Serialize(savedXray, Json) == JsonSerializer.Serialize(incoming.Xray, Json);
    }

    public async Task BumpAsync(CancellationToken ct = default)
    {
        await _db.Cluster.Where(c => c.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(c => c.Revision, c => c.Revision + 1), ct);
        Changes.Signal();
    }

    /// <summary>Signal a revision change that was committed as part of a larger transaction.</summary>
    public void SignalRevisionChanged() => Changes.Signal();

    /// <summary>Сигнал «что-то изменилось» для агентов, ждущих в длинном опросе.</summary>
    public static readonly ChangeSignal Changes = new();

    public sealed class ChangeSignal
    {
        private TaskCompletionSource _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task Next => Volatile.Read(ref _tcs).Task;
        public void Signal() => Interlocked.Exchange(ref _tcs, new(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult();
    }

    /// <summary>Адрес для пользователей: вход/домен из настроек, иначе активный выход.</summary>
    public async Task<string> PublicHostAsync(ClusterIdentity c, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(c.PublicHost)) return c.PublicHost.Trim();
        var entry = await _db.Servers.Where(s => s.Role == ServerRoles.Entry && s.TargetExitId != null).OrderBy(s => s.CreatedAt).FirstOrDefaultAsync(ct);
        if (entry != null) return entry.Host;
        var exit = await _db.Servers.Where(s => s.Role == ServerRoles.Exit && s.Active).FirstOrDefaultAsync(ct)
                   ?? await _db.Servers.Where(s => s.Role == ServerRoles.Exit).OrderBy(s => s.CreatedAt).FirstOrDefaultAsync(ct);
        return exit?.Host ?? "";
    }

    /// <summary>
    /// Адрес для готовых файлов доступа (iPhone, Mac и другие устройства без приложения Маяк): основной выход,
    /// отмеченный в админке активным. Ключи устройств есть на всех выходах, поэтому файл работает напрямую.
    /// Нет активного выхода — прежнее правило <see cref="PublicHostAsync"/>. Приложение Маяк выбирает сервер само и сюда не ходит.
    /// </summary>
    public async Task<string> AccessHostAsync(ClusterIdentity c, CancellationToken ct)
    {
        var active = await _db.Servers.AsNoTracking().Where(s => s.Role == ServerRoles.Exit && s.Active && s.Host != "")
            .OrderBy(s => s.CreatedAt).Select(s => s.Host).FirstOrDefaultAsync(ct);
        return string.IsNullOrWhiteSpace(active) ? await PublicHostAsync(c, ct) : active.Trim();
    }

    /// <summary>Свободный адрес в подсети VPN (тот же на всех выходах).</summary>
    public async Task<string> AllocateIpAsync(ClusterIdentity c, IEnumerable<string>? alsoTaken = null, CancellationToken ct = default)
    {
        var awg = AwgOf(c);
        var used = await _db.Devices.Select(d => d.Ip).ToListAsync(ct);
        var reserved = await ReservedIpsAsync(ct);
        // У AmneziaWG адрес интерфейса сервера совпадает с адресом подсети (10.8.1.0/24).
        return IpAllocator.Next(awg.SubnetAddress, int.Parse(awg.SubnetCidr), awg.SubnetAddress,
            used.Concat(reserved).Concat(alsoTaken ?? Array.Empty<string>()));
    }

    /// <summary>Адреса, занятые на серверах не через API (по отчётам агентов).</summary>
    private async Task<List<string>> ReservedIpsAsync(CancellationToken ct)
    {
        var reports = await _db.Servers.Where(s => s.LastReport != null).Select(s => s.LastReport!).ToListAsync(ct);
        var list = new List<string>();
        foreach (var r in reports)
        {
            try { list.AddRange(JsonSerializer.Deserialize<AgentReport>(r, Json)?.ReservedIps ?? new()); }
            catch (JsonException) { /* старый формат отчёта */ }
        }
        return list;
    }

    /// <summary>Что должно стоять на сервере.</summary>
    public Task<AgentState> StateForAsync(Server server, CancellationToken ct) =>
        WithPoolStateAsync(now => StateForSnapshotAsync(server, now, ct), ct);

    private async Task<AgentState> StateForSnapshotAsync(Server server, DateTime now, CancellationToken ct)
    {
        var c = await _db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
        var state = new AgentState { Revision = c?.Revision ?? 0, Role = server.Role, DefaultDownMbps = 35, DefaultUpMbps = 35 };
        if (server.Role == ServerRoles.Entry)
        {
            // Authentication can precede a long poll. Observe the persisted
            // assignment again rather than using its earlier tracked value.
            var entry = await _db.Servers.AsNoTracking().Where(s => s.Id == server.Id)
                .Select(s => new { s.TargetExitId }).FirstOrDefaultAsync(ct);
            if (entry == null) throw new RelayTargetUnavailableException();
            if (entry.TargetExitId is Guid target)
            {
                var exit = await _db.Servers.AsNoTracking().FirstOrDefaultAsync(s => s.Id == target, ct);
                // Relay=null explicitly removes the existing relay in current
                // agents. A configured but unsafe target must deny the whole
                // state read, preserving the agent's last-known configuration.
                if (c == null || exit == null || exit.Role != ServerRoles.Exit ||
                    (exit.ProvisioningStatus != null && !ProvisioningGuards.IsReady(exit, c, now)) ||
                    await ProvisioningGuards.HostExistsAsync(_db, exit.Host, exit.Id, ct))
                    throw new RelayTargetUnavailableException();
                var awg = AwgOf(c);
                state.Relay = new AgentRelay { TargetHost = exit.Host, AwgPort = awg.Port, XrayPort = XrayOf(c)?.Port };
            }
            return state;
        }

        var endpoint = await _db.ExitEndpoints.FirstOrDefaultAsync(e => e.ServerId == server.Id, ct);
        if (endpoint != null)
        {
            state.PoolEndpoint = new AgentPoolEndpoint
            {
                EndpointId = endpoint.Id,
                IdentityVersion = endpoint.IdentityVersion,
                DesiredCredentialsRevision = endpoint.AppliedCredentialsRevision,
                Host = endpoint.Host, Port = endpoint.Port, PublicKey = endpoint.PublicKey, Sni = endpoint.Sni,
                ShortId = endpoint.ShortId, Flow = endpoint.Flow, Transport = endpoint.Transport,
                Fingerprint = endpoint.Fingerprint, XhttpPath = endpoint.XhttpPath, XhttpHost = endpoint.XhttpHost,
                XhttpMode = endpoint.XhttpMode, AllowNewConnections = endpoint.AllowNewConnections,
                CapacitySlots = endpoint.CapacitySlots,
            };
            state.PoolDevices = await (from d in _db.Devices.AsNoTracking()
                where d.ServiceProtocol == "vless" && d.ExitEndpointId == endpoint.Id && d.Account != null && d.Account.Enabled && (d.Account.PaidUntil == null || d.Account.PaidUntil > now)
                select new AgentPoolDevice { DeviceId = d.Id, Enabled = d.Enabled, XrayId = d.XrayId, CredentialsRevision = d.CredentialsRevision,
                    EndpointId = endpoint.Id, Host = endpoint.Host, Port = endpoint.Port, PublicKey = endpoint.PublicKey,
                    Sni = endpoint.Sni, ShortId = endpoint.ShortId, Flow = endpoint.Flow, Transport = endpoint.Transport,
                    Fingerprint = endpoint.Fingerprint, XhttpPath = endpoint.XhttpPath, XhttpHost = endpoint.XhttpHost, XhttpMode = endpoint.XhttpMode }).ToListAsync(ct);
        }
        var accounts = await _db.Accounts.Include(a => a.Devices).AsNoTracking().ToListAsync(ct);
        state.Accounts = accounts.Select(a => new AgentAccount
        {
            Id = a.Id,
            Name = a.Name,
            Enabled = a.IsActive(now),
            Devices = a.Devices.Where(d => d.ServiceProtocol != "vless").Select(d => new AgentDevice
            {
                Id = d.Id,
                Name = d.Name,
                Kind = d.Kind,
                PublicKey = d.AwgPublicKey,
                Ip = d.Ip,
                XrayId = d.XrayId,
                Enabled = d.Enabled,
                DownMbps = d.DownMbps ?? a.DownMbps,
                UpMbps = d.UpMbps ?? a.UpMbps,
            }).ToList(),
        }).ToList();
        return state;
    }

    public static bool IsPoolReady(ExitEndpoint e, DateTime now) => e.AllowNewConnections && e.CapacitySlots > 0 &&
        e.ProtocolReportReceivedAt is DateTime received && received >= now - PoolReportFreshness && received <= now &&
        e.ReportedIdentityVersion == e.IdentityVersion && e.ReportedCredentialsRevision == e.AppliedCredentialsRevision &&
        e.RuntimeReady && e.ConfigValid && e.SelfTestPassed && !e.DryRun && string.IsNullOrEmpty(e.ProtocolError);

    /// <summary>Serialize a readiness observation with membership writers and reconcile clock expiry at one snapshot time.</summary>
    public async Task<T> WithPoolStateAsync<T>(Func<DateTime, Task<T>> observe, CancellationToken ct)
    {
        var ownsTransaction = _db.Database.CurrentTransaction == null;
        await using var tx = ownsTransaction ? await _db.Database.BeginTransactionAsync(ct) : null;
        await DeviceWriteLock.AcquireAsync(_db, ct);
        var now = DateTime.UtcNow;
        await ReconcilePoolCredentialsAsync(now, ct);
        T result;
        try { result = await observe(now); }
        catch (Exception ex) when (ex is PoolDeliveryException or RelayTargetUnavailableException)
        {
            // A denied delivery must still persist clock-expiry reconciliation.
            if (tx != null) await tx.CommitAsync(ct);
            throw;
        }
        if (tx != null) await tx.CommitAsync(ct);
        return result;
    }

    /// <summary>
    /// Caller holds the device advisory transaction lock and has saved pending membership writes.
    /// The fingerprint mirrors PoolDevices (including Enabled), never capacity occupancy.
    /// Reconcile both before and after access mutations so an unobserved expiry plus renewal cannot reuse an old ACK.
    /// </summary>
    public async Task ReconcilePoolCredentialsAsync(DateTime now, CancellationToken ct)
    {
        if (_db.Database.CurrentTransaction == null) throw new InvalidOperationException("Pool reconciliation requires the device transaction lock");
        var endpoints = await _db.ExitEndpoints.ToListAsync(ct);
        bool changed = false;
        foreach (var endpoint in endpoints)
        {
            // A context may have loaded metadata before waiting for another writer's lock.
            await _db.Entry(endpoint).ReloadAsync(ct);
            var members = await _db.Devices.AsNoTracking()
                .Where(d => d.ServiceProtocol == "vless" && d.ExitEndpointId == endpoint.Id && d.Account != null &&
                    d.Account.Enabled && (d.Account.PaidUntil == null || d.Account.PaidUntil > now))
                .OrderBy(d => d.Id).Select(d => new { d.Id, d.XrayId, d.Enabled }).ToListAsync(ct);
            var hash = Tokens.Hash(JsonSerializer.Serialize(members));
            if (hash == endpoint.DesiredCredentialsHash) continue;
            endpoint.DesiredCredentialsHash = hash;
            endpoint.AppliedCredentialsRevision++;
            endpoint.ProtocolReportReceivedAt = null;
            changed = true;
        }
        if (!changed) return;
        await _db.SaveChangesAsync(ct);
        await BumpAsync(ct);
    }

    /// <summary>Assigns once under the caller's transaction/advisory lock; slots are never released without revocation ACK.</summary>
    public async Task<ExitEndpoint?> AssignPoolEndpointAsync(Device device, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        await ReconcilePoolCredentialsAsync(now, ct);
        if (!await _db.Devices.AsNoTracking().AnyAsync(d => d.Id == device.Id && d.Enabled && d.Account != null &&
            d.Account.Enabled && (d.Account.PaidUntil == null || d.Account.PaidUntil > now), ct)) return null;
        if (device.ExitEndpointId is Guid assigned)
        {
            var existing = await _db.ExitEndpoints.FirstOrDefaultAsync(e => e.Id == assigned, ct);
            return existing != null && IsPoolReady(existing, now) ? existing : null;
        }
        var choices = await _db.ExitEndpoints.Where(e => e.AllowNewConnections && e.OccupiedSlots < e.CapacitySlots).ToListAsync(ct);
        var selected = choices.Where(e => IsPoolReady(e, now))
            .OrderBy(e => (double)e.OccupiedSlots / e.CapacitySlots).ThenBy(e => e.Id).FirstOrDefault();
        if (selected == null) return null;
        selected.OccupiedSlots++;
        device.ServiceProtocol = "vless";
        device.ExitEndpointId = selected.Id;
        await _db.SaveChangesAsync(ct);
        // Keep allocation and its desired credential payload at the same clock snapshot.
        await ReconcilePoolCredentialsAsync(now, ct);
        device.CredentialsRevision = selected.AppliedCredentialsRevision;
        await _db.SaveChangesAsync(ct);
        return selected;
    }

    /// <summary>
    /// Переносит в API людей и устройства, которых на выходе завёл Маяк для Windows.
    /// Безопасно повторять: устройство с уже известным ключом пропускается, ключи и адреса не меняются —
    /// выданные файлы продолжают работать. Так ни одно подключение с сервера не потеряется,
    /// даже если в API уже есть другие устройства.
    /// </summary>
    public async Task<int> ImportLegacyAsync(MayakDatabase legacy, CancellationToken ct)
    {
        var knownKeys = (await _db.Devices.Select(d => d.AwgPublicKey).ToListAsync(ct)).ToHashSet();
        var usedIps = (await _db.Devices.Select(d => d.Ip).ToListAsync(ct)).ToHashSet();
        int count = 0;
        foreach (var u in legacy.Users)
        {
            var fresh = u.Devices.Where(d => !string.IsNullOrEmpty(d.PublicKey) && !string.IsNullOrEmpty(d.Ip) && !knownKeys.Contains(d.PublicKey)).ToList();
            if (fresh.Count == 0) continue;

            var acc = await _db.Accounts.FirstOrDefaultAsync(a => a.Id == u.Id, ct)
                      ?? await _db.Accounts.FirstOrDefaultAsync(a => a.Legacy && a.Name == u.Name, ct);
            if (acc == null)
            {
                acc = new Account
                {
                    Id = u.Id,
                    Name = u.Name,
                    Note = u.Note,
                    Enabled = u.Enabled,
                    Legacy = true,
                    MaxDevices = Math.Max(3, u.Devices.Count),
                    DownMbps = legacy.DefaultDownMbps,
                    UpMbps = legacy.DefaultUpMbps,
                    CreatedAt = DateTime.SpecifyKind(u.CreatedAt, DateTimeKind.Utc),
                };
                _db.Accounts.Add(acc);
            }
            foreach (var d in fresh)
            {
                if (usedIps.Contains(d.Ip)) continue; // адрес занят другим ключом — такого быть не должно, не трогаем
                _db.Devices.Add(new Device
                {
                    Id = d.Id,
                    AccountId = acc.Id,
                    Name = d.Name,
                    Kind = d.Kind,
                    AwgPublicKey = d.PublicKey,
                    AwgPrivateKey = string.IsNullOrEmpty(d.PrivateKey) ? null : d.PrivateKey,
                    Ip = d.Ip,
                    XrayId = string.IsNullOrEmpty(d.XrayId) ? Guid.NewGuid().ToString() : d.XrayId,
                    Enabled = d.Enabled,
                    DownMbps = d.DownMbps == legacy.DefaultDownMbps ? null : d.DownMbps,
                    UpMbps = d.UpMbps == legacy.DefaultUpMbps ? null : d.UpMbps,
                    CreatedAt = DateTime.SpecifyKind(d.CreatedAt, DateTimeKind.Utc),
                });
                knownKeys.Add(d.PublicKey);
                usedIps.Add(d.Ip);
                count++;
            }
        }
        if (count == 0) return 0;
        await _db.SaveChangesAsync(ct);
        await BumpAsync(ct);
        return count;
    }

    /// <summary>Устройство с ключами, созданными сервером (для своих людей: файл выдаёт администратор).</summary>
    public async Task<Device> CreateManagedDeviceAsync(Account acc, string name, DeviceKind kind, CancellationToken ct, string? protocol = null, string? installationId = null)
    {
        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        await DeviceWriteLock.AcquireAsync(_db, ct);
        await _db.Entry(acc).ReloadAsync(ct);
        if (!acc.IsActive(DateTime.UtcNow)) throw new InvalidOperationException("Доступ не активен");
        if (!string.IsNullOrWhiteSpace(installationId))
        {
            var existing = await _db.Devices.FirstOrDefaultAsync(d => d.AccountId == acc.Id && d.InstallationId == installationId, ct);
            if (existing != null)
            {
                if (existing.ServiceProtocol != protocol) throw new InvalidOperationException("Установка уже зарегистрирована с другим протоколом.");
                bool wasUnassigned = existing.ExitEndpointId == null;
                if (protocol == "vless" && wasUnassigned) await AssignPoolEndpointAsync(existing, ct);
                await tx.CommitAsync(ct);
                if (protocol == "vless" && wasUnassigned && existing.ExitEndpointId != null) await BumpAsync(ct);
                return existing;
            }
        }
        await DeviceWriteLock.EnsureRoomAsync(_db, acc, ct);
        var c = await GetAsync(ct) ?? throw new InvalidOperationException("Нет ни одного выхода: сначала подключите сервер.");
        var (priv, pub) = Curve25519.GenerateKeyPair();
        var d = new Device
        {
            AccountId = acc.Id,
            Name = name,
            Kind = kind,
            AwgPublicKey = pub,
            AwgPrivateKey = priv,
            Ip = await AllocateIpAsync(c, null, ct),
            XrayId = Guid.NewGuid().ToString(),
            ServiceProtocol = protocol,
            InstallationId = installationId,
        };
        _db.Devices.Add(d);
        await _db.SaveChangesAsync(ct);
        if (protocol == "vless") await AssignPoolEndpointAsync(d, ct);
        await tx.CommitAsync(ct);
        await BumpAsync(ct);
        return d;
    }

    /// <summary>Всё, что нужно человеку, чтобы подключить устройство в готовых приложениях.</summary>
    public sealed record DeviceFiles(string VpnKey, string Conf, string ConfName, string? Vless, string QrConf, string? QrVless);

    public async Task<DeviceFiles> BuildDeviceFilesAsync(Device d, Account acc, CancellationToken ct)
    {
        if (d.ServiceProtocol == "vless")
        {
            return await WithPoolStateAsync(async now =>
            {
                await _db.Entry(d).ReloadAsync(ct);
                await _db.Entry(acc).ReloadAsync(ct);
                if (_db.Entry(d).State == EntityState.Detached) throw new PoolDeliveryException("device_not_found", 404);
                if (!d.Enabled || !acc.IsActive(now)) throw new PoolDeliveryException("access_not_active", 403);
                if (d.ExitEndpointId is not Guid endpointId) throw new PoolDeliveryException("no_ready_exit", 503);
                var endpoint = await _db.ExitEndpoints.FirstOrDefaultAsync(e => e.Id == endpointId, ct);
                if (endpoint == null) throw new PoolDeliveryException("no_ready_exit", 503);
                if (!IsPoolReady(endpoint, now)) throw new PoolDeliveryException("provisioning", 503);
                var root = Mayak.Api.Gateway.GatewayEndpoints.PoolClientConfig(d, endpoint);
                var poolKey = Mayak.Core.Export.VpnKeyCodec.Encode(root.ToJsonString());
                var native = Mayak.Core.Xray.XrayConfig.BuildClientJson(endpoint.Host, Mayak.Api.Gateway.GatewayEndpoints.PoolXrayOf(endpoint), d.XrayId);
                var link = Mayak.Api.Gateway.GatewayEndpoints.BuildPoolLink(endpoint, d);
                var filename = Mayak.Core.Export.Transliteration.ToTunnelName("mayak-" + d.Name) + ".json";
                return new DeviceFiles(poolKey, native, filename, link, Qr(poolKey), Qr(link));
            }, ct);
        }
        var (key, conf) = await BuildFilesAsync(d, acc, ct);
        var c = (await GetAsync(ct))!;
        var xray = ClientXrayOf(c);
        string? vless = null;
        if (xray != null && !string.IsNullOrEmpty(d.XrayId))
            vless = Mayak.Core.Xray.XrayConfig.BuildVlessLink(await PublicHostAsync(c, ct), xray, d.XrayId, $"{c.Title} · {d.Name}");
        var confName = Mayak.Core.Export.Transliteration.ToTunnelName("mayak-" + d.Name) + ".conf";
        return new DeviceFiles(key, conf, confName, vless, Qr(conf), vless == null ? null : Qr(vless));
    }

    private static string Qr(string text) => "data:image/png;base64," + Convert.ToBase64String(Mayak.Core.Export.QrImages.Png(text, 6));

    /// <summary>Город активного выхода — для карточки в кабинете и приложении.</summary>
    public async Task<object?> LocationAsync(CancellationToken ct)
    {
        var s = await _db.Servers.Where(x => x.Role == ServerRoles.Exit && x.Active).FirstOrDefaultAsync(ct);
        return s == null ? null : new { s.City, s.Country, s.CountryCode, s.Fact, s.PhotoUrl, online = s.LastSeen > DateTime.UtcNow.AddMinutes(-3) };
    }

    /// <summary>Конфигурация для приложения AmneziaVPN/AmneziaWG по сохранённому ключу устройства.</summary>
    public async Task<(string VpnKey, string Conf)> BuildFilesAsync(Device d, Account acc, CancellationToken ct)
    {
        // Keep the lower-level legacy export entry point from bypassing pool readiness.
        if (d.ServiceProtocol == "vless")
        {
            var pool = await BuildDeviceFilesAsync(d, acc, ct);
            return (pool.VpnKey, pool.Conf);
        }
        if (string.IsNullOrEmpty(d.AwgPrivateKey)) throw new InvalidOperationException("Ключ этого устройства хранится только на нём самом.");
        var c = await GetAsync(ct) ?? throw new InvalidOperationException("Нет общих ключей выходов.");
        var ep = AwgOf(c);
        ep.Host = await AccessHostAsync(c, ct);
        var vd = new VpnDevice
        {
            Id = d.Id, Name = d.Name, Kind = d.Kind, PrivateKey = d.AwgPrivateKey, PublicKey = d.AwgPublicKey,
            Ip = d.Ip, XrayId = d.XrayId,
        };
        var xray = ClientXrayOf(c);
        var title = $"{c.Title} · {acc.Name}";
        var key = Mayak.Core.Export.ClientConfigFactory.BuildVpnKey(ep, vd, c.Dns1, c.Dns2, title, xray);
        var conf = Mayak.Core.Export.ClientConfigFactory.BuildConfFile(ep, vd, c.Dns1, c.Dns2);
        return (key, conf);
    }
}

public sealed class RelayTargetUnavailableException() : InvalidOperationException("relay_target_unready");

public sealed class PoolDeliveryException(string error, int statusCode) : InvalidOperationException(error)
{
    public int StatusCode { get; } = statusCode;
}
