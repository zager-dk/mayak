using System.Security.Cryptography;
using System.Text;

namespace Mayak.Api.Services;

/// <summary>Случайные токены: клиенту — сам токен, в базу — только его SHA-256.</summary>
public static class Tokens
{
    public static string New(int bytes = 32) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    /// <summary>Токен из заголовка Authorization: Bearer …</summary>
    public static string? FromRequest(HttpRequest request)
    {
        var h = request.Headers.Authorization.ToString();
        return h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? h[7..].Trim() : null;
    }
}
