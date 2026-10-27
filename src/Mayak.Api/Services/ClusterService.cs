using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Core.Agent;
using Mayak.Core.Crypto;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

/// <summary>Общие ключи выходов, выдача адресов в VPN, состояние для агентов.</summary>
public sealed class ClusterService
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    private readonly MayakDb _db;

    public ClusterService(MayakDb db) => _db = db;

    public Task<ClusterIdentity?> GetAsync(CancellationToken ct = default) => _db.Cluster.FirstOrDefaultAsync(c => c.Id == 1, ct);

    public static ServerEndpoint AwgOf(ClusterIdentity c) => JsonSerializer.Deserialize<ServerEndpoint>(c.AwgJson, Json) ?? new ServerEndpoint();

    public static XrayEndpoint? XrayOf(ClusterIdentity c) =>
        string.IsNullOrEmpty(c.XrayJson) ? null : JsonSerializer.Deserialize<XrayEndpoint>(c.XrayJson, Json);

    /// <summary>Запоминает ключи первого выхода как общие для всех. Возвращает false, если общие ключи уже есть.</summary>
    public async Task<bool> AdoptIdentityAsync(AgentIdentity id, CancellationToken ct)
    {
        if (await GetAsync(ct) != null) return false;
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
        return true;
    }

    public async Task BumpAsync(CancellationToken ct = default)
    {
        await _db.Cluster.Where(c => c.Id == 1).ExecuteUpdateAsync(s => s.SetProperty(c => c.Revision, c => c.Revision + 1), ct);
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
    public async Task<AgentState> StateForAsync(Server server, CancellationToken ct)
    {
        var c = await GetAsync(ct);
        var state = new AgentState { Revision = c?.Revision ?? 0, Role = server.Role, DefaultDownMbps = 35, DefaultUpMbps = 35 };
        if (server.Role == ServerRoles.Entry)
        {
            if (server.TargetExitId is Guid target && c != null)
            {
                var exit = await _db.Servers.FirstOrDefaultAsync(s => s.Id == target, ct);
                var awg = AwgOf(c);
                if (exit != null)
                    state.Relay = new AgentRelay { TargetHost = exit.Host, AwgPort = awg.Port, XrayPort = XrayOf(c)?.Port };
            }
            return state;
        }

        var now = DateTime.UtcNow;
        var accounts = await _db.Accounts.Include(a => a.Devices).AsNoTracking().ToListAsync(ct);
        state.Accounts = accounts.Select(a => new AgentAccount
        {
            Id = a.Id,
            Name = a.Name,
            Enabled = a.IsActive(now),
            Devices = a.Devices.Select(d => new AgentDevice
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

    /// <summary>Переносит пользователей Маяка для Windows с выхода в API (один раз, пока устройств нет).</summary>
    public async Task<int> ImportLegacyAsync(MayakDatabase legacy, CancellationToken ct)
    {
        if (await _db.Devices.AnyAsync(ct)) return 0;
        int count = 0;
        foreach (var u in legacy.Users)
        {
            var acc = new Account
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
            foreach (var d in u.Devices.Where(d => !string.IsNullOrEmpty(d.PublicKey) && !string.IsNullOrEmpty(d.Ip)))
            {
                acc.Devices.Add(new Device
                {
                    Id = d.Id,
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
                count++;
            }
            _db.Accounts.Add(acc);
        }
        await _db.SaveChangesAsync(ct);
        await BumpAsync(ct);
        return count;
    }

    /// <summary>Устройство с ключами, созданными сервером (для своих людей: файл выдаёт администратор).</summary>
    public async Task<Device> CreateManagedDeviceAsync(Account acc, string name, DeviceKind kind, CancellationToken ct)
    {
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
        };
        _db.Devices.Add(d);
        await _db.SaveChangesAsync(ct);
        await BumpAsync(ct);
        return d;
    }

    /// <summary>Конфигурация для приложения AmneziaVPN/AmneziaWG по сохранённому ключу устройства.</summary>
    public async Task<(string VpnKey, string Conf)> BuildFilesAsync(Device d, Account acc, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(d.AwgPrivateKey)) throw new InvalidOperationException("Ключ этого устройства хранится только на нём самом.");
        var c = await GetAsync(ct) ?? throw new InvalidOperationException("Нет общих ключей выходов.");
        var ep = AwgOf(c);
        ep.Host = await PublicHostAsync(c, ct);
        var vd = new VpnDevice
        {
            Id = d.Id, Name = d.Name, Kind = d.Kind, PrivateKey = d.AwgPrivateKey, PublicKey = d.AwgPublicKey,
            Ip = d.Ip, XrayId = d.XrayId,
        };
        var xray = XrayOf(c);
        var title = $"{c.Title} · {acc.Name}";
        var key = Mayak.Core.Export.ClientConfigFactory.BuildVpnKey(ep, vd, c.Dns1, c.Dns2, title, xray);
        var conf = Mayak.Core.Export.ClientConfigFactory.BuildConfFile(ep, vd, c.Dns1, c.Dns2);
        return (key, conf);
    }
}
