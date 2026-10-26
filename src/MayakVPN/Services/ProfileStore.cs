using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mayak.Core.Server;

namespace MayakVPN.Services;

/// <summary>Сервер в списке приложения. Пароли зашифрованы DPAPI (расшифровать может только этот пользователь Windows).</summary>
public sealed class ServerProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string User { get; set; } = "root";
    public string? EncryptedPassword { get; set; }
    public string? KeyPath { get; set; }
    public string? EncryptedPassphrase { get; set; }
    public string? Fingerprint { get; set; }

    public override string ToString() => Name;

    [JsonIgnore]
    public string? Password
    {
        get => Unprotect(EncryptedPassword);
        set => EncryptedPassword = Protect(value);
    }

    [JsonIgnore]
    public string? Passphrase
    {
        get => Unprotect(EncryptedPassphrase);
        set => EncryptedPassphrase = Protect(value);
    }

    public SshCredentials ToCredentials() => new()
    {
        Host = Host.Trim(),
        Port = Port,
        User = User.Trim(),
        Password = Password,
        PrivateKeyPath = string.IsNullOrWhiteSpace(KeyPath) ? null : KeyPath,
        PrivateKeyPassphrase = Passphrase,
        KnownHostFingerprint = Fingerprint,
    };

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("MayakVPN.v1");

    private static string? Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Entropy, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(data);
    }

    private static string? Unprotect(string? cipher)
    {
        if (string.IsNullOrEmpty(cipher)) return null;
        try
        {
            var data = ProtectedData.Unprotect(Convert.FromBase64String(cipher), Entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(data);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}

public sealed class AppSettings
{
    public List<ServerProfile> Servers { get; set; } = new();
    public Guid? LastServerId { get; set; }
    public string? ExportFolder { get; set; }
}

public static class ProfileStore
{
    public static string Folder { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MayakVPN");
    private static string FilePath => Path.Combine(Folder, "settings.json");

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
        }
        catch (Exception)
        {
            var backup = FilePath + ".broken";
            try { File.Copy(FilePath, backup, overwrite: true); } catch { /* ignore */ }
        }
        return new AppSettings();
    }

    public static void Save(AppSettings settings)
    {
        Directory.CreateDirectory(Folder);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Options));
        File.Move(tmp, FilePath, overwrite: true);
    }

    public static string DefaultExportFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Маяк VPN");
}
