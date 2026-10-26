using System.Text;
using Mayak.Core.Models;
using Mayak.Core.Server;

namespace Mayak.Core.Export;

/// <summary>Файлы доступа на компьютере: «папка/сервер/пользователь/файл».</summary>
public static class AccessFiles
{
    public static string Title(ServerSnapshot snap, VpnUser user) => $"{snap.Db.ServerTitle} · {user.Name}";

    public static string FolderFor(string exportFolder, ServerSnapshot snap, VpnUser user) =>
        Path.Combine(exportFolder, Safe(snap.Db.ServerTitle), Safe(user.Name));

    /// <summary>Сохраняет файл в формате, подходящем устройству (.vpn или .conf); для .conf — ещё и QR-картинку.</summary>
    public static string Save(string exportFolder, ServerSnapshot snap, VpnUser user, VpnDevice device)
    {
        var format = device.Kind.DefaultFormat();
        var folder = FolderFor(exportFolder, snap, user);
        Directory.CreateDirectory(folder);
        var file = Path.Combine(folder, ClientConfigFactory.SuggestFileName(user.Name, device, format));
        var db = snap.Db;
        if (format == ConfigFormat.AwgConf)
        {
            var conf = ClientConfigFactory.BuildConfFile(snap.Endpoint, device, db.Dns1, db.Dns2);
            File.WriteAllText(file, conf, new UTF8Encoding(false));
            File.WriteAllBytes(Path.ChangeExtension(file, ".png"), QrImages.Png(conf));
        }
        else
        {
            var xray = string.IsNullOrEmpty(device.XrayId) ? null : snap.Xray;
            var key = ClientConfigFactory.BuildVpnKey(snap.Endpoint, device, db.Dns1, db.Dns2, Title(snap, user), xray);
            File.WriteAllText(file, key, new UTF8Encoding(false));
        }
        return file;
    }

    /// <summary>Сохраняет файлы для всех устройств и сводку «Доступы.txt». Возвращает папку сервера.</summary>
    public static string SaveAll(string exportFolder, ServerSnapshot snap, IEnumerable<GrantItem> items)
    {
        var list = items.Where(i => i.Device.CanExport).ToList();
        var serverFolder = Path.Combine(exportFolder, Safe(snap.Db.ServerTitle));
        Directory.CreateDirectory(serverFolder);
        var sb = new StringBuilder();
        sb.AppendLine($"Доступы к «{snap.Db.ServerTitle}» ({snap.Endpoint.Host}), {DateTime.Now:dd.MM.yyyy HH:mm}");
        sb.AppendLine();
        foreach (var group in list.GroupBy(i => i.User))
        {
            sb.AppendLine(group.Key.Name + (group.Key.Enabled ? "" : " (доступ приостановлен)"));
            foreach (var i in group)
            {
                var path = Save(exportFolder, snap, i.User, i.Device);
                sb.AppendLine($"  {i.Device.Name} ({i.Device.Kind.Title()}): {Path.GetRelativePath(serverFolder, path)}{(i.Created ? "  — новый" : "")}");
            }
            sb.AppendLine();
        }
        sb.AppendLine("Windows и Android: файл .vpn → приложение AmneziaVPN.");
        sb.AppendLine("iPhone и Mac: файл .conf (или QR из .png) → приложение AmneziaWG.");
        File.WriteAllText(Path.Combine(serverFolder, "Доступы.txt"), sb.ToString(), new UTF8Encoding(false));
        return serverFolder;
    }

    public static string Safe(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return name.Trim().Length == 0 ? "_" : name.Trim();
    }
}
