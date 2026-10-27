using Mayak.Core.Models;

namespace Mayak.Api.Data;

public static class Roles
{
    public const string User = "user";
    public const string Support = "support";
    public const string Admin = "admin";
    public const string Owner = "owner";

    public static readonly string[] All = { User, Support, Admin, Owner };

    public static int Rank(string role) => role switch
    {
        Owner => 3,
        Admin => 2,
        Support => 1,
        _ => 0,
    };
}

/// <summary>Аккаунт человека. Минимум данных: Telegram ID или почта, тариф, срок.</summary>
public sealed class Account
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public long? TelegramId { get; set; }
    public string? TelegramUsername { get; set; }
    public string? Email { get; set; }
    public string Role { get; set; } = Roles.User;
    public bool Enabled { get; set; } = true;
    public string Note { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Доступ оплачен до (UTC). null — без срока (свои люди).</summary>
    public DateTime? PaidUntil { get; set; }
    public int MaxDevices { get; set; } = 3;
    public int DownMbps { get; set; } = 35;
    public int UpMbps { get; set; } = 35;

    /// <summary>Перенесён из Маяка для Windows (у его устройств есть приватные ключи для повторной выдачи файла).</summary>
    public bool Legacy { get; set; }

    public List<Device> Devices { get; set; } = new();

    public bool IsActive(DateTime now) => Enabled && (PaidUntil == null || PaidUntil > now);
}

/// <summary>Устройство. Ключ AmneziaWG создаёт само приложение; на сервер приходит только открытый.</summary>
public sealed class Device
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AccountId { get; set; }
    public Account? Account { get; set; }
    public string Name { get; set; } = "";
    public DeviceKind Kind { get; set; } = DeviceKind.Other;
    public string AwgPublicKey { get; set; } = "";
    /// <summary>Только у перенесённых из Маяка для Windows: чтобы выдать файл заново.</summary>
    public string? AwgPrivateKey { get; set; }
    public string Ip { get; set; } = "";
    public string XrayId { get; set; } = "";
    public bool Enabled { get; set; } = true;
    /// <summary>Свой лимит устройства, Мбит/с; null — по тарифу аккаунта.</summary>
    public int? DownMbps { get; set; }
    public int? UpMbps { get; set; }
    public string? InstallationId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastHandshake { get; set; }
    public long RxBytes { get; set; }
    public long TxBytes { get; set; }
}

public static class ServerRoles
{
    public const string Exit = "exit";
    public const string Entry = "entry";
}

/// <summary>Сервер сети: выход за рубежом или вход в России. Управляется агентом.</summary>
public sealed class Server
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Role { get; set; } = ServerRoles.Exit;
    public string Host { get; set; } = "";
    public string City { get; set; } = "";
    public string Country { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string Fact { get; set; } = "";
    public string? PhotoUrl { get; set; }
    /// <summary>SHA-256 токена агента (сам токен показывается один раз).</summary>
    public string AgentTokenHash { get; set; } = "";
    /// <summary>Выход, через который сейчас идёт трафик.</summary>
    public bool Active { get; set; }
    /// <summary>Для входа: на какой выход пересылать.</summary>
    public Guid? TargetExitId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastSeen { get; set; }
    public string? AgentVersion { get; set; }
    public string? LastError { get; set; }
    /// <summary>Последний отчёт агента (JSON): пиры, проверки.</summary>
    public string? LastReport { get; set; }
}

/// <summary>
/// Общие для всех выходов ключи и параметры: выходы — клоны, поэтому пользователь
/// не замечает переключения. Одна строка (Id = 1).
/// </summary>
public sealed class ClusterIdentity
{
    public int Id { get; set; } = 1;
    /// <summary>ServerEndpoint без адреса: ключ сервера, PSK, порт, подсеть, параметры AWG (JSON).</summary>
    public string AwgJson { get; set; } = "";
    public string AwgServerPrivateKey { get; set; } = "";
    /// <summary>XrayEndpoint (JSON) и закрытый ключ Reality; пусто — Xray нет.</summary>
    public string? XrayJson { get; set; }
    public string? XrayPrivateKey { get; set; }
    public string Dns1 { get; set; } = "1.1.1.1";
    public string Dns2 { get; set; } = "1.0.0.1";
    /// <summary>Адрес для пользователей: вход или домен. Пусто — адрес активного выхода.</summary>
    public string PublicHost { get; set; } = "";
    public string Title { get; set; } = "Маяк VPN";
    /// <summary>Растёт при любом изменении, влияющем на серверы: агенты сверяются по нему.</summary>
    public long Revision { get; set; } = 1;
}

/// <summary>Вход через Telegram: приложение создаёт запрос, человек подтверждает его в боте.</summary>
public sealed class LoginRequest
{
    public string Id { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public long? TelegramId { get; set; }
    public string? TelegramUsername { get; set; }
    public string? TelegramName { get; set; }
    public Guid? AccountId { get; set; }
    public bool Consumed { get; set; }
}

/// <summary>Сеанс приложения: хранится только хеш токена.</summary>
public sealed class Session
{
    public string TokenHash { get; set; } = "";
    public Guid AccountId { get; set; }
    public Account? Account { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastUsed { get; set; } = DateTime.UtcNow;
    public string Client { get; set; } = "";
}

/// <summary>Журнал действий администраторов и агентов.</summary>
public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
    public Guid? ActorId { get; set; }
    public string Action { get; set; } = "";
    public string Details { get; set; } = "";
}
