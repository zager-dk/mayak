using System.Collections.Concurrent;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;

namespace Mayak.Api.Provisioning;

public sealed class ProvisioningCoordinator(IProvisioningBackend backend, IServiceScopeFactory scopes, IHostApplicationLifetime lifetime)
{
    private readonly SemaphoreSlim _capacity = new(2, 2);
    private readonly ConcurrentDictionary<string, Guid> _targets = new(StringComparer.Ordinal);

    public bool TryReserve(string host, out ProvisioningReservation? reservation)
    {
        reservation = null;
        if (!_capacity.Wait(0)) return false;
        var id = Guid.NewGuid();
        if (!_targets.TryAdd(host, id))
        {
            _capacity.Release();
            return false;
        }
        reservation = new ProvisioningReservation(this, host, id);
        return true;
    }

    private void Release(string host, Guid id)
    {
        if (_targets.TryGetValue(host, out var current) && current == id) _targets.TryRemove(host, out _);
        _capacity.Release();
    }

    private async Task RunAsync(Guid serverId, string host, ProvisioningCredentials credentials, string agentToken,
        ProvisioningPlan plan, string publicUrl, Guid actorId, string sessionHash, bool overwrite)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
        linked.CancelAfter(TimeSpan.FromMinutes(30));
        var ct = linked.Token;
        string phase = "queued";
        try
        {
            await SetStatusAsync(serverId, "preflight", "Повторная проверка перед установкой.", ct);
            ProvisioningInstallContext context;
            using (var scope = scopes.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
                var server = await db.Servers.FirstAsync(s => s.Id == serverId, ct);
                if (server.Active || server.ProvisioningStatus != "preflight") throw new ProvisioningException("Provision row is not eligible");
                if (!await ProvisioningEndpoints.IsCurrentEnabledAdminAsync(db, actorId, sessionHash, ct))
                {
                    server.ProvisioningStatus = "failed";
                    server.ProvisioningMessage = "Административный доступ отозван до начала установки; удалённые изменения не выполнялись.";
                    server.ProvisioningUpdatedAt = DateTime.UtcNow;
                    await db.SaveChangesAsync(ct);
                    return;
                }
                var cluster = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
                var otherServerExists = await db.Servers.AnyAsync(s => s.Id != serverId, ct);
                if (cluster == null && otherServerExists) throw new ProvisioningException("Existing agents must initialize cluster identity before provisioning another server");
                if (cluster != null)
                {
                    var currentHash = ProvisioningPlanner.IdentityHash(cluster);
                    if (plan.BootstrapIdentity || currentHash != plan.IdentityVersionHash)
                        throw new ProvisioningException("Cluster identity changed after target inspection");
                }
                else if (!plan.BootstrapIdentity)
                {
                    throw new ProvisioningException("Cluster identity disappeared after target inspection");
                }
                server.ProvisioningStatus = "installing";
                server.ProvisioningMessage = "Подключение подтверждено; установка началась.";
                server.ProvisioningUpdatedAt = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
                context = new ProvisioningInstallContext(serverId, server.Name, credentials, plan, cluster, agentToken, publicUrl, overwrite);
            }

            await backend.InstallAsync(context, async key =>
            {
                phase = key;
                var (status, message) = key switch
                {
                    "overwriting" => ("overwriting", "Сервер не пустой: прежние настройки сохраняются в архив на сервере, контейнеры, VPN и агент удаляются."),
                    "installing_awg" => ("installing_awg", "Установка AmneziaWG; существующие серверы не меняются."),
                    "installing_xray" => ("installing_xray", "Установка Xray с согласованной кластерной identity."),
                    "installing_agent" => ("installing_agent", "Загрузка агента и настройка systemd."),
                    "awaiting_agent" => ("awaiting_agent", "Ожидание связи агента и подтверждения синхронизации."),
                    _ => throw new ProvisioningException("Unknown provisioning phase"),
                };
                await SetStatusAsync(serverId, status, message, ct);
            }, ct);

            for (var i = 0; i < 150; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var scope = scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
                var server = await db.Servers.AsNoTracking().FirstOrDefaultAsync(s => s.Id == serverId, ct);
                if (server == null) throw new ProvisioningException("Provisioning server was deleted");
                if (server.ProvisioningStatus == "installed") return;
                if (server.ProvisioningStatus == "failed") throw new ProvisioningException("Agent rejected identity or failed synchronization");
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
            throw new ProvisioningException("Agent did not confirm synchronization before timeout");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            await SetStatusAsync(serverId, "interrupted", "Установка прервана остановкой API; сервер оставлен неактивным, требуется ручная проверка.", CancellationToken.None);
        }
        catch (Exception)
        {
            var message = phase == "awaiting_agent"
                ? "Агент не подтвердил совпадение identity и синхронизацию. Сервер оставлен неактивным; автоматическая очистка не выполнялась."
                : "Установка остановлена на текущем шаге. Сервер оставлен неактивным; автоматическая очистка не выполнялась.";
            await SetStatusAsync(serverId, "failed", message, CancellationToken.None);
        }
        finally
        {
            credentials.Password = "";
            agentToken = "";
            sessionHash = "";
        }
    }

    private async Task SetStatusAsync(Guid id, string status, string message, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        await db.Servers.Where(s => s.Id == id).ExecuteUpdateAsync(u => u
            .SetProperty(s => s.ProvisioningStatus, status)
            .SetProperty(s => s.ProvisioningMessage, message)
            .SetProperty(s => s.ProvisioningUpdatedAt, DateTime.UtcNow), ct);
    }

    public sealed class ProvisioningReservation : IDisposable
    {
        private readonly ProvisioningCoordinator _owner;
        private readonly string _host;
        private readonly Guid _reservationId;
        private int _finished;

        internal ProvisioningReservation(ProvisioningCoordinator owner, string host, Guid reservationId)
        {
            _owner = owner;
            _host = host;
            _reservationId = reservationId;
        }

        public Guid JobId => _reservationId;

        public void Start(Guid serverId, ProvisioningCredentials credentials, string agentToken, ProvisioningPlan plan, string publicUrl, Guid actorId, string sessionHash, bool overwrite = false)
        {
            if (Interlocked.Exchange(ref _finished, 1) != 0) throw new InvalidOperationException("Reservation already completed");
            _ = Task.Run(async () =>
            {
                try { await _owner.RunAsync(serverId, _host, credentials, agentToken, plan, publicUrl, actorId, sessionHash, overwrite); }
                finally { _owner.Release(_host, _reservationId); }
            });
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _finished, 1) == 0) _owner.Release(_host, _reservationId);
        }
    }
}

public sealed record ProvisioningHostKeyRequest(string Host, int Port = 22);
public sealed class ProvisioningInspectRequest
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public string TrustedFingerprint { get; set; } = "";
    public bool TrustFingerprint { get; set; }
}
public sealed class ProvisioningStartRequest
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public string TrustedFingerprint { get; set; } = "";
    public bool TrustFingerprint { get; set; }
    public string Name { get; set; } = "";
    public string? City { get; set; }
    public string? Country { get; set; }
    public int AwgPort { get; set; }
    public int XrayPort { get; set; }
    public bool ConfirmBlankServer { get; set; }
    /// <summary>Сервер не пустой: перезаписать (архив прежнего на сервере, удаление контейнеров, VPN и агента).</summary>
    public bool Overwrite { get; set; }
}

public static class ProvisioningPlanner
{
    public static async Task<(ProvisioningPlan? Plan, string? Error)> GetAsync(MayakDb db, int? bootstrapAwgPort, int? bootstrapXrayPort, Guid? currentServerId, CancellationToken ct)
    {
        var cluster = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, ct);
        if (cluster == null)
        {
            if (await db.Servers.AnyAsync(s => currentServerId == null || s.Id != currentServerId, ct))
                return (null, "Кластерная identity ещё не зарегистрирована. Дождитесь связи агента существующего выхода.");
            var awg = bootstrapAwgPort ?? Mayak.Core.Server.InstallOptions.RandomPort();
            var xray = bootstrapXrayPort ?? Mayak.Core.Models.XrayDefaults.DefaultPort;
            if (!ValidPorts(awg, xray)) return (null, "Некорректные порты установки.");
            return (new ProvisioningPlan(awg, xray, true, "bootstrap"), null);
        }
        var awgEndpoint = ClusterService.AwgOf(cluster);
        var xrayEndpoint = ClusterService.XrayOf(cluster);
        if (string.IsNullOrWhiteSpace(cluster.AwgServerPrivateKey) || string.IsNullOrWhiteSpace(awgEndpoint.ServerPublicKey) ||
            string.IsNullOrWhiteSpace(awgEndpoint.PresharedKey) || xrayEndpoint == null || string.IsNullOrWhiteSpace(cluster.XrayPrivateKey))
            return (null, "Общая identity AWG + Xray неполная. До установки требуется безопасно завершить синхронизацию Xray в кластере.");
        if (!ValidPorts(awgEndpoint.Port, xrayEndpoint.Port)) return (null, "В кластерной identity заданы некорректные порты.");
        if (bootstrapAwgPort is int ap && ap != awgEndpoint.Port || bootstrapXrayPort is int xp && xp != xrayEndpoint.Port)
            return (null, "Кластерные порты изменились после проверки. Выполните проверку сервера ещё раз.");
        return (new ProvisioningPlan(awgEndpoint.Port, xrayEndpoint.Port, false, IdentityHash(cluster)), null);
    }

    /// <summary>
    /// Отпечаток identity выхода: только то, что должно совпадать на сервере (ключи и параметры AWG/Xray).
    /// Название и DNS сюда не входят: серверы их не используют, а правка в админке не должна снимать подтверждение выходов.
    /// </summary>
    public static string IdentityHash(ClusterIdentity c) => Mayak.Api.Services.Tokens.Hash(string.Join('\n',
        "identity-v2", c.AwgJson, c.AwgServerPrivateKey, c.XrayJson ?? "", c.XrayPrivateKey ?? ""));

    /// <summary>Прежняя формула (до 11.2026, с DNS и названием): хэши, сохранённые старым API, принимаются до первого отчёта агента.</summary>
    public static string LegacyIdentityHash(ClusterIdentity c) => Mayak.Api.Services.Tokens.Hash(string.Join('\n',
        c.AwgJson, c.AwgServerPrivateKey, c.XrayJson ?? "", c.XrayPrivateKey ?? "", c.Dns1, c.Dns2, c.Title));

    public static bool IdentityHashMatches(string? stored, ClusterIdentity c) =>
        stored != null && (stored == IdentityHash(c) || stored == LegacyIdentityHash(c));

    private static bool ValidPorts(int awg, int xray) => awg is > 0 and <= 65535 && xray is > 0 and <= 65535 && awg != xray;
}
