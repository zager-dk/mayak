using System.Text.RegularExpressions;
using Mayak.Api.Data;
using Mayak.Api.Telegram;
using Mayak.Core.Crypto;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Services;

public sealed record DeviceKeyRequest(string? InstallationId, string? DeviceHash, string? Os, string? AppVersion, Guid? ReplaceDeviceId);

public sealed record DeviceKeyOutcome(int Status, string? Error = null, string? Code = null, string? Token = null,
    Device? Device = null, IReadOnlyList<Device>? Devices = null, int MaxDevices = 0, bool Reused = false);

/// <summary>Правила ключей устройств: токен md1.… выдаётся одной установке приложения, в базе только его SHA-256.</summary>
public static partial class DeviceAccess
{
    public const string TokenPrefix = "md1.";

    public static bool IsDeviceToken(string? key) =>
        key != null && key.Length > TokenPrefix.Length && key.Length <= 128 && key.StartsWith(TokenPrefix, StringComparison.Ordinal);

    public static string NewToken() => TokenPrefix + Tokens.New(32);

    /// <summary>Последний признак жизни: рукопожатие, получение настроек или создание.</summary>
    public static DateTime LastSeen(Device d)
    {
        var seen = d.CreatedAt;
        if (d.ConfigFetchedAt is DateTime f && f > seen) seen = f;
        if (d.LastHandshake is DateTime h && h > seen) seen = h;
        return seen;
    }

    /// <summary>
    /// Ключ из запроса шлюза разрешает действовать от имени устройства: токен устройства — только для своего устройства,
    /// ключ аккаунта — только для устройств, ещё не получивших свой токен.
    /// </summary>
    public static bool KeyAuthorizes(Account account, Device device, string? key)
    {
        if (key == null || device.AccountId != account.Id) return false;
        if (IsDeviceToken(key)) return device.AppTokenHash != null && string.Equals(device.AppTokenHash, Tokens.Hash(key), StringComparison.Ordinal);
        return device.AppTokenHash == null && account.AppKey != null && string.Equals(account.AppKey, key, StringComparison.Ordinal);
    }

    /// <summary>
    /// Завершение старой попытки подключения (release/reconcile): кроме текущего ключа подходит предыдущий ключ этой
    /// установки. Эти действия только освобождают место; без этого смена ключа при включённом VPN оставляла бы
    /// попытку, которую нельзя закрыть (OFF/ON переставали работать).
    /// </summary>
    public static bool CleanupAuthorizes(Account account, Device device, string? key) =>
        KeyAuthorizes(account, device, key) || key != null && device.AccountId == account.Id &&
        device.PreviousAppTokenHash != null && string.Equals(device.PreviousAppTokenHash, Tokens.Hash(key), StringComparison.Ordinal);

    /// <summary>Хеш постоянного ID в пределах аккаунта: одно устройство в разных аккаунтах по базе не связывается.</summary>
    public static string ScopedDeviceHash(Guid accountId, string deviceHash) => Tokens.Hash($"{accountId:N}:{deviceHash}");

    public static DeviceKind KindOf(string? os) => (os ?? "").ToLowerInvariant() switch
    {
        var s when s.Contains("ios") => DeviceKind.IPhone,
        var s when s.Contains("android") => DeviceKind.Android,
        var s when s.Contains("windows") => DeviceKind.Windows,
        var s when s.Contains("mac") || s.Contains("osx") => DeviceKind.Mac,
        var s when s.Length > 0 => DeviceKind.Linux,
        _ => DeviceKind.Other,
    };

    public static bool ValidInstallationId(string? s) => s != null && InstallationPattern().IsMatch(s);
    public static bool ValidDeviceHash(string? s) => s != null && HashPattern().IsMatch(s);

    [GeneratedRegex("^[A-Za-z0-9{}-]{8,128}$")] private static partial Regex InstallationPattern();
    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex HashPattern();

    public static object View(Device d) => new
    {
        d.Id,
        d.Name,
        kind = d.Kind.ToString(),
        os = d.OsVersion,
        lastSeen = LastSeen(d),
    };
}

public sealed class DeviceAccessService(MayakDb db, ClusterService cluster, IConfiguration cfg, TelegramClient tg, ILogger<DeviceAccessService> log)
{
    public int InactiveDays => Math.Clamp(cfg.GetValue("Devices:InactiveDays", 30), 1, 3650);

    public async Task<DeviceKeyOutcome> IssueAsync(Account acc, DeviceKeyRequest req, CancellationToken ct)
    {
        var install = req.InstallationId?.Trim();
        if (!DeviceAccess.ValidInstallationId(install)) return new(400, "installationId is required");
        var rawHash = string.IsNullOrWhiteSpace(req.DeviceHash) ? null : req.DeviceHash.Trim().ToLowerInvariant();
        if (rawHash != null && !DeviceAccess.ValidDeviceHash(rawHash)) return new(400, "deviceHash must be SHA-256 hex");
        var hash = rawHash == null ? null : DeviceAccess.ScopedDeviceHash(acc.Id, rawHash);
        var os = Clip(req.Os, 64);
        var appVersion = Clip(req.AppVersion, 32);
        var now = DateTime.UtcNow;

        var released = new List<Device>();
        Device? replaced = null;
        Device? device;
        bool created = false;
        string token = DeviceAccess.NewToken();
        int count;

        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            await DeviceWriteLock.AcquireAsync(db, ct);
            await cluster.ReconcilePoolCredentialsAsync(now, ct);
            await db.Entry(acc).ReloadAsync(ct);
            if (db.Entry(acc).State == EntityState.Detached) return new(401, "Account not found");
            if (!acc.Enabled) return new(403, "Доступ ещё не одобрен");
            if (!acc.IsActive(now)) return new(403, "Срок доступа закончился");

            var devices = await db.Devices.Where(d => d.AccountId == acc.Id).OrderBy(d => d.CreatedAt).ToListAsync(ct);
            device = devices.FirstOrDefault(d => d.InstallationId == install);
            bool reinstalled = false;
            if (device == null && hash != null)
            {
                device = devices.Where(d => d.StableDeviceHash == hash && d.ServiceProtocol != "vless")
                    .OrderByDescending(DeviceAccess.LastSeen).FirstOrDefault();
                reinstalled = device != null;
            }
            if (device != null)
            {
                if (!device.Enabled) return new(403, "Устройство отключено. Обратитесь к администратору.");
                if (device.ServiceProtocol == "vless") return new(409, "Установка зарегистрирована для VLESS");
                if (reinstalled) device.InstallationId = install;
                // Новый ключ: прежний остаётся только для завершения старых попыток, а места устройства на серверах
                // освобождаются, чтобы следующее подключение с новым ключом не упёрлось в «уже подключено».
                device.PreviousAppTokenHash = device.AppTokenHash ?? (acc.AppKey != null ? Tokens.Hash(acc.AppKey) : null);
                await db.AwgAllocations.Where(a => a.DeviceId == device.Id && a.ReleasedAt == null)
                    .ExecuteUpdateAsync(u => u.SetProperty(a => a.ReleasedAt, now), ct);
            }
            else
            {
                if (devices.Count >= acc.MaxDevices)
                {
                    var cutoff = now.AddDays(-InactiveDays);
                    // Отключённые администратором устройства не освобождаются: иначе блокировка снималась бы сама.
                    foreach (var stale in devices.Where(d => d.Enabled && d.InstallationId != null && d.ServiceProtocol != "vless" && DeviceAccess.LastSeen(d) < cutoff)
                                 .OrderBy(DeviceAccess.LastSeen))
                    {
                        if (devices.Count - released.Count < acc.MaxDevices) break;
                        released.Add(stale);
                    }
                }
                if (devices.Count - released.Count >= acc.MaxDevices && req.ReplaceDeviceId is Guid replaceId)
                {
                    replaced = devices.FirstOrDefault(d => d.Id == replaceId && !released.Contains(d));
                    if (replaced == null) return new(404, "Устройство для замены не найдено");
                    if (!replaced.Enabled) return new(403, "Это устройство отключено администратором, заменить его нельзя.");
                }
                int remaining = devices.Count - released.Count - (replaced == null ? 0 : 1);
                if (remaining >= acc.MaxDevices)
                    return new(409, $"Можно не больше {acc.MaxDevices} устройств. Выберите, какое заменить.", "DEVICE_LIMIT",
                        Devices: devices, MaxDevices: acc.MaxDevices);

                var c = await cluster.GetAsync(ct);
                if (c == null) return new(503, "Нет ни одного выхода");
                foreach (var d in released) db.Devices.Remove(d);
                if (replaced != null) db.Devices.Remove(replaced);
                await db.SaveChangesAsync(ct);

                var kind = DeviceAccess.KindOf(os);
                // Ключ AmneziaWG приложение создаст при первом получении настроек; до этого — случайный открытый ключ без пары.
                var (_, placeholder) = Curve25519.GenerateKeyPair();
                device = new Device
                {
                    AccountId = acc.Id,
                    Name = UniqueName(Endpoints.AppEndpoints.KindName(kind), devices.Except(released).Where(d => d != replaced)),
                    Kind = kind,
                    AwgPublicKey = placeholder,
                    Ip = await cluster.AllocateIpAsync(c, null, ct),
                    XrayId = Guid.NewGuid().ToString(),
                    InstallationId = install,
                    // Ключ устройства получает только новое приложение, а оно всегда подключается через допуск к серверам:
                    // устройство не должно считаться «старым» и занимать место на каждом выходе до первых настроек.
                    AutoConnectManaged = true,
                };
                db.Devices.Add(device);
                created = true;
            }

            device.StableDeviceHash = hash ?? device.StableDeviceHash;
            device.AppTokenHash = Tokens.Hash(token);
            device.OsVersion = os ?? device.OsVersion;
            device.AppVersion = appVersion ?? device.AppVersion;
            var details = created ? $"new {device.Name}" : reinstalled ? $"reinstall {device.Name}" : $"rotate {device.Name}";
            if (released.Count > 0) details += $" released={released.Count}";
            if (replaced != null) details += $" replaced={replaced.Name}";
            db.Audit.Add(new AuditEntry { ActorId = acc.Id, Action = "app.device-key", Details = details });
            await db.SaveChangesAsync(ct);
            await cluster.ReconcilePoolCredentialsAsync(now, ct);
            count = await db.Devices.CountAsync(d => d.AccountId == acc.Id, ct);
            await tx.CommitAsync(ct);
        }
        if (released.Count > 0 || replaced != null) await cluster.BumpAsync(ct);
        if (created) await NotifyAsync(acc, device, count, released, replaced, ct);
        return new(200, Token: token, Device: device, MaxDevices: acc.MaxDevices, Reused: !created);
    }

    private static string UniqueName(string baseName, IEnumerable<Device> others)
    {
        var taken = others.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!taken.Contains(baseName)) return baseName;
        for (int i = 2; ; i++)
            if (!taken.Contains($"{baseName} {i}")) return $"{baseName} {i}";
    }

    private static string? Clip(string? s, int max)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim();
        return t.Length > max ? t[..max] : t;
    }

    /// <summary>Уведомление в Telegram владельцу аккаунта и администраторам. Ошибка отправки не мешает выдаче ключа.</summary>
    private async Task NotifyAsync(Account acc, Device device, int count, List<Device> released, Device? replaced, CancellationToken ct)
    {
        if (!tg.Enabled) return;
        var chats = new HashSet<long>();
        if (acc.TelegramId is long own) chats.Add(own);
        if (cfg.GetValue("Devices:NotifyAdmins", true))
            foreach (var id in await db.Accounts.Where(a => a.TelegramId != null && (a.Role == Roles.Owner || a.Role == Roles.Admin))
                         .Select(a => a.TelegramId!.Value).ToListAsync(ct))
                chats.Add(id);
        if (chats.Count == 0) return;
        var os = string.IsNullOrEmpty(device.OsVersion) ? "" : $" ({device.OsVersion})";
        var text = $"Новое устройство в аккаунте «{acc.Name}»: {device.Name}{os}. Устройств: {count} из {acc.MaxDevices}.";
        if (replaced != null) text += $"\nЗаменено: {replaced.Name}.";
        if (released.Count > 0) text += $"\nОсвобождено неактивных: {string.Join(", ", released.Select(d => d.Name))}.";
        text += "\nЕсли это не вы — отключите устройство в приложении или напишите администратору.";
        _ = Task.Run(async () =>
        {
            foreach (var chat in chats)
            {
                try { await tg.SendAsync(chat, text, CancellationToken.None); }
                catch (Exception ex) { log.LogWarning("Уведомление об устройстве не отправлено: {Error}", ex.Message); }
            }
        }, CancellationToken.None);
    }
}
