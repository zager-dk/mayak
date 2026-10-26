using System.IO;
using Mayak.Core.Probe;

namespace MayakVPN.Services;

/// <summary>
/// Данные для «Проверки» без SSH, по одному файлу на сервер (%APPDATA%\MayakVPN\checkkit\*.dat),
/// зашифрованы DPAPI: в них ключ проверочной учётки.
/// </summary>
public static class CheckKitStore
{
    private static string Dir => Path.Combine(ProfileStore.Folder, "checkkit");
    private static string PathFor(Guid id) => Path.Combine(Dir, id.ToString("N") + ".dat");

    public static void Save(Guid serverId, CheckKit kit)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(PathFor(serverId), ServerProfile.Protect(kit.ToJson()) ?? "");
        }
        catch (Exception) { /* не мешаем основной работе */ }
    }

    public static CheckKit? Load(Guid serverId)
    {
        try
        {
            var path = PathFor(serverId);
            if (!File.Exists(path)) return null;
            var json = ServerProfile.Unprotect(File.ReadAllText(path));
            return json == null ? null : CheckKit.FromJson(json);
        }
        catch (Exception) { return null; }
    }

    public static void Delete(Guid serverId)
    {
        try { File.Delete(PathFor(serverId)); } catch (Exception) { /* ignore */ }
    }
}
