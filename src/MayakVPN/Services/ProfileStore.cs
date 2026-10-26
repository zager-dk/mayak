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

    /// <summary>"main" — VPN-сервер, "relay" — входной сервер каскада.</summary>
    public string Role { get; set; } = "main";

    /// <summary>Для основного сервера: входной сервер (каскад).</summary>
    public Guid? RelayProfileId { get; set; }
    public string? RelayHost { get; set; }
    /// <summary>Управлять основным сервером по SSH через вход (порт RelaySshPort на входе).</summary>
    public bool ManageViaRelay { get; set; }
    public int RelaySshPort { get; set; } = 22022;

    /// <summary>
    /// Маяк подключается к этому серверу по SSH через другой сервер из списка (SSH-туннель, как ssh -J).
    /// Нужно, когда зарубежный сервер не открывается из домашней сети.
    /// </summary>
    public Guid? JumpProfileId { get; set; }

    /// <summary>Для входного сервера: какому основному он служит.</summary>
    public Guid? RelayForProfileId { get; set; }

    [JsonIgnore]
    public bool IsRelay => Role == "relay";

    [JsonIgnore]
    public string Subtitle => IsRelay ? $"{Host} · вход (каскад)"
        : RelayHost != null ? $"{Host} · через вход {RelayHost}"
        : JumpProfileId != null ? $"{Host} · Маяк через посредника"
        : Host;

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
        Host = ManageViaRelay && !string.IsNullOrEmpty(RelayHost) ? RelayHost.Trim() : Host.Trim(),
        Port = ManageViaRelay && !string.IsNullOrEmpty(RelayHost) ? RelaySshPort : Port,
        User = User.Trim(),
        Password = Password,
        PrivateKeyPath = string.IsNullOrWhiteSpace(KeyPath) ? null : KeyPath,
        PrivateKeyPassphrase = Passphrase,
        KnownHostFingerprint = Fingerprint,
    };

    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("MayakVPN.v1");

    internal static string? Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Entropy, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(data);
    }

    internal static string? Unprotect(string? cipher)
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
