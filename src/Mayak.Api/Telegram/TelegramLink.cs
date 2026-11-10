using Mayak.Api.Data;

namespace Mayak.Api.Telegram;

/// <summary>Общие правила привязки Telegram к аккаунту с почтой и паролем.</summary>
public static class TelegramLink
{
    /// <summary>
    /// Аккаунт, уже связанный с этим Telegram, можно заменить при привязке, только если он пустой: создан входом через бота,
    /// без пароля, без устройств и без особой роли.
    /// </summary>
    public static bool IsReplaceable(Account other, bool hasDevices) =>
        other.Role == Roles.User && other.PasswordHash == null && !hasDevices;
}
