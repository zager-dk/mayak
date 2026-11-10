using System.Security.Cryptography;
using System.Text;

namespace Mayak.Api.Services;

public static class PasswordCredentials
{
    public const int Iterations = 600_000;
    private const string Prefix = "pbkdf2-sha256$v1$";
    private static readonly byte[] DummySalt = RandomNumberGenerator.GetBytes(16);
    private static readonly byte[] DummyHash = Rfc2898DeriveBytes.Pbkdf2("dummy-password-never-valid", DummySalt, Iterations, HashAlgorithmName.SHA256, 32);

    public static string NormalizeEmail(string? email)
    {
        var value = email?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > 254 || value.Any(char.IsControl)) throw new ArgumentException("Введите корректный адрес электронной почты.");
        var at = value.LastIndexOf('@');
        if (at < 1 || at == value.Length - 1 || value[..at].Contains('@') || value.Any(char.IsWhiteSpace)) throw new ArgumentException("Введите корректный адрес электронной почты.");
        try { if (new System.Net.Mail.MailAddress(value).Address != value) throw new FormatException(); }
        catch { throw new ArgumentException("Введите корректный адрес электронной почты."); }
        return value.ToUpperInvariant();
    }

    public static bool ValidPassword(string? password) => password is { Length: >= 12 and <= 128 } && password.All(c => !char.IsControl(c));

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"{Prefix}{Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string? encoded)
    {
        if (!TryParse(encoded, out var iterations, out var salt, out var expected))
        {
            var dummy = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), DummySalt, Iterations, HashAlgorithmName.SHA256, 32);
            CryptographicOperations.FixedTimeEquals(dummy, DummyHash);
            return false;
        }
        var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool TryParse(string? encoded, out int iterations, out byte[] salt, out byte[] expected)
    {
        iterations = 0; salt = Array.Empty<byte>(); expected = Array.Empty<byte>();
        try
        {
            if (string.IsNullOrEmpty(encoded) || encoded.Length > 256) return false;
            var p = encoded?.Split('$');
            if (p is not { Length: 5 } || p[0] != "pbkdf2-sha256" || p[1] != "v1" || !int.TryParse(p[2], out iterations) || iterations is < Iterations or > 1_000_000) return false;
            salt = Convert.FromBase64String(p[3]); expected = Convert.FromBase64String(p[4]);
            return salt.Length is >= 16 and <= 64 && expected.Length == 32;
        }
        catch { return false; }
    }
}
