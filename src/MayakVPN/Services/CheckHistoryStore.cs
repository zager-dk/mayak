using System.IO;
using System.Text.Json;
using Mayak.Core.Probe;

namespace MayakVPN.Services;

/// <summary>История проверок протоколов по каждому серверу (%APPDATA%\MayakVPN\checks.json).</summary>
public static class CheckHistoryStore
{
    private static string FilePath => Path.Combine(ProfileStore.Folder, "checks.json");
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static List<CheckReport> Load(Guid serverId)
    {
        var all = LoadAll();
        return all.TryGetValue(serverId.ToString(), out var list) ? list : new List<CheckReport>();
    }

    public static void Add(Guid serverId, CheckReport report)
    {
        var all = LoadAll();
        var key = serverId.ToString();
        if (!all.TryGetValue(key, out var list)) all[key] = list = new List<CheckReport>();
        list.Insert(0, report);
        if (list.Count > 50) list.RemoveRange(50, list.Count - 50);
        Directory.CreateDirectory(ProfileStore.Folder);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(all, Options));
    }

    private static Dictionary<string, List<CheckReport>> LoadAll()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Dictionary<string, List<CheckReport>>>(File.ReadAllText(FilePath), Options) ?? new();
        }
        catch (Exception) { /* испорченная история не мешает работе */ }
        return new();
    }

    /// <summary>Папка для служебных программ (xray.exe).</summary>
    public static string ToolsFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MayakVPN");
}
