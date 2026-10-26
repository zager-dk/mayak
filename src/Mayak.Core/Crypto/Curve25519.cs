using System.Numerics;
using System.Security.Cryptography;

namespace Mayak.Core.Crypto;

/// <summary>
/// X25519 (RFC 7748) — то же, что делают «awg genkey» / «awg pubkey».
/// Реализация через BigInteger: медленнее нативной, но ключи генерируются
/// по одному на устройство, так что скорость не важна.
/// </summary>
public static class Curve25519
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger A24 = 121665;
    private static readonly byte[] BasePoint = CreateBasePoint();

    private static byte[] CreateBasePoint()
    {
        var b = new byte[32];
        b[0] = 9;
        return b;
    }

    /// <summary>Пара ключей WireGuard/AmneziaWG в base64.</summary>
    public static (string PrivateKey, string PublicKey) GenerateKeyPair()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        Clamp(priv);
        var pub = ScalarMult(priv, BasePoint);
        return (Convert.ToBase64String(priv), Convert.ToBase64String(pub));
    }

    /// <summary>Публичный ключ из приватного (base64 → base64).</summary>
    public static string PublicKeyFromPrivate(string privateKeyBase64)
    {
        var priv = Convert.FromBase64String(privateKeyBase64);
        if (priv.Length != 32) throw new ArgumentException("Приватный ключ должен быть 32 байта");
        return Convert.ToBase64String(ScalarMult(priv, BasePoint));
    }

    /// <summary>Случайный 32-байтный ключ (как «awg genpsk»).</summary>
    public static string GeneratePresharedKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static void Clamp(byte[] k)
    {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }

    public static byte[] ScalarMult(byte[] scalar, byte[] uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32)
            throw new ArgumentException("Скаляр и координата должны быть по 32 байта");

        var k = (byte[])scalar.Clone();
        Clamp(k);
        var kInt = new BigInteger(k, isUnsigned: true, isBigEndian: false);

        var u = (byte[])uCoordinate.Clone();
        u[31] &= 127;
        var x1 = Mod(new BigInteger(u, isUnsigned: true, isBigEndian: false));

        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        int swap = 0;

        for (int t = 254; t >= 0; t--)
        {
            int kt = (int)((kInt >> t) & 1);
            swap ^= kt;
            if (swap == 1)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }
            swap = kt;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);

            var sum = Mod(da + cb);
            x3 = Mod(sum * sum);
            var diff = Mod(da - cb);
            z3 = Mod(x1 * Mod(diff * diff));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + A24 * e));
        }

        if (swap == 1)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        var result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
        var bytes = result.ToByteArray(isUnsigned: true, isBigEndian: false);
        var output = new byte[32];
        Array.Copy(bytes, output, Math.Min(bytes.Length, 32));
        return output;
    }

    private static BigInteger Mod(BigInteger x)
    {
        var r = x % P;
        return r.Sign < 0 ? r + P : r;
    }
}
