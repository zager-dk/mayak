using System.IO;
using System.Text.Encodings.Web;
using System.Text.Json;
using Mayak.Core.Models;

namespace MayakVPN.Services;

/// <summary>Постоянный список людей (%APPDATA%\MayakVPN\people.json), общий для всех серверов.</summary>
public static class PeopleStore
{
    private static string FilePath => Path.Combine(ProfileStore.Folder, "people.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static List<Person> Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<List<Person>>(File.ReadAllText(FilePath), Options) ?? new();
        }
        catch (Exception)
        {
            try { File.Copy(FilePath, FilePath + ".broken", overwrite: true); } catch { /* ignore */ }
        }
        return new();
    }

    public static void Save(IEnumerable<Person> people)
    {
        Directory.CreateDirectory(ProfileStore.Folder);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(people.ToList(), Options));
        File.Move(tmp, FilePath, overwrite: true);
    }
}
