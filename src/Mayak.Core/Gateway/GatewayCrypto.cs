using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mayak.Core.Gateway;

/// <summary>
/// Конверт запросов шлюза подписки — тот же, что у приложения Amnezia (библиотека libagw).
/// Запрос: {"key_payload": base64(RSA-PKCS#1 v1.5({"aes_key","aes_iv","aes_salt"})), "api_payload": base64(AES-256-CBC(json))}.
/// Ответ: сырые байты AES-256-CBC(json) тем же ключом.
/// Особенности протокола, на которые рассчитывает клиент: «iv» передаётся как 32 байта, а CBC берёт первые 16;
/// соль передаётся, но не используется.
/// </summary>
public static class GatewayCrypto
{
    private const int KeyBytes = 32, IvBytes = 32, Block = 16, SaltBytes = 8;

    private sealed class Keys
    {
        [JsonPropertyName("aes_key")] public string AesKey { get; set; } = "";
        [JsonPropertyName("aes_iv")] public string AesIv { get; set; } = "";
        [JsonPropertyName("aes_salt")] public string AesSalt { get; set; } = "";
    }

    private sealed class Body
    {
        [JsonPropertyName("key_payload")] public string KeyPayload { get; set; } = "";
        [JsonPropertyName("api_payload")] public string ApiPayload { get; set; } = "";
    }

    /// <summary>Сессия одного запроса: ключ и IV, которыми шифруется ответ.</summary>
    public sealed record Session(byte[] Key, byte[] Iv);

    /// <summary>Сервер: расшифровывает запрос закрытым ключом шлюза.</summary>
    public static (string Json, Session Session) OpenRequest(string requestBody, RSA privateKey)
    {
        Body body;
        try
        {
            body = JsonSerializer.Deserialize<Body>(requestBody) ?? throw new GatewayCryptoException("пустой запрос");
        }
        catch (JsonException ex)
        {
            throw new GatewayCryptoException("запрос не JSON", ex);
        }
        if (body.KeyPayload.Length == 0 || body.ApiPayload.Length == 0)
            throw new GatewayCryptoException("нет key_payload или api_payload");

        byte[] keysJson;
        try
        {
            keysJson = privateKey.Decrypt(Convert.FromBase64String(body.KeyPayload), RSAEncryptionPadding.Pkcs1);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new GatewayCryptoException("не удалось расшифровать ключ запроса", ex);
        }

        var keys = JsonSerializer.Deserialize<Keys>(keysJson) ?? throw new GatewayCryptoException("пустые ключи");
        var key = Convert.FromBase64String(keys.AesKey);
        var iv = Convert.FromBase64String(keys.AesIv);
        if (key.Length != KeyBytes || iv.Length < Block)
            throw new GatewayCryptoException("неверная длина ключа или IV");

        var session = new Session(key, iv);
        try
        {
            var json = Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(body.ApiPayload), session));
            return (json, session);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new GatewayCryptoException("не удалось расшифровать тело запроса", ex);
        }
    }

    /// <summary>Сервер: шифрует ответ ключом сессии.</summary>
    public static byte[] SealResponse(string json, Session session) => Encrypt(Encoding.UTF8.GetBytes(json), session);

    /// <summary>Клиент (тесты, Маяк для Windows): собирает запрос открытым ключом шлюза.</summary>
    public static (string Body, Session Session) SealRequest(string json, RSA publicKey)
    {
        var key = RandomNumberGenerator.GetBytes(KeyBytes);
        var iv = RandomNumberGenerator.GetBytes(IvBytes);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var keysJson = JsonSerializer.SerializeToUtf8Bytes(new Keys
        {
            AesKey = Convert.ToBase64String(key),
            AesIv = Convert.ToBase64String(iv),
            AesSalt = Convert.ToBase64String(salt),
        });
        var session = new Session(key, iv);
        var body = JsonSerializer.Serialize(new Body
        {
            KeyPayload = Convert.ToBase64String(publicKey.Encrypt(keysJson, RSAEncryptionPadding.Pkcs1)),
            ApiPayload = Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(json), session)),
        });
        return (body, session);
    }

    /// <summary>Клиент: расшифровывает ответ.</summary>
    public static string OpenResponse(byte[] body, Session session) => Encoding.UTF8.GetString(Decrypt(body, session));

    private static byte[] Encrypt(byte[] data, Session s)
    {
        using var aes = Aes.Create();
        aes.Key = s.Key;
        return aes.EncryptCbc(data, s.Iv.AsSpan(0, Block), PaddingMode.PKCS7);
    }

    private static byte[] Decrypt(byte[] data, Session s)
    {
        using var aes = Aes.Create();
        aes.Key = s.Key;
        return aes.DecryptCbc(data, s.Iv.AsSpan(0, Block), PaddingMode.PKCS7);
    }

    /// <summary>Новая пара ключей шлюза (RSA 2048): закрытый — на сервере API, открытый — вшивается в приложение.</summary>
    public static (string PrivatePem, string PublicPem) GenerateKeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }
}

public sealed class GatewayCryptoException : Exception
{
    public GatewayCryptoException(string message, Exception? inner = null) : base(message, inner) { }
}
