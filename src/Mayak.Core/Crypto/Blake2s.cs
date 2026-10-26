using System.Buffers.Binary;
using System.Numerics;

namespace Mayak.Core.Crypto;

/// <summary>BLAKE2s (RFC 7693) — хеш WireGuard. Поддерживает ключ и длину 1–32 байта.</summary>
public static class Blake2s
{
    private static readonly uint[] IV =
    {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    private static readonly byte[,] Sigma =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };

    public static byte[] Hash(int outLen, ReadOnlySpan<byte> key, params byte[][] parts)
    {
        if (outLen is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(outLen));
        if (key.Length > 32) throw new ArgumentOutOfRangeException(nameof(key));

        var h = (uint[])IV.Clone();
        h[0] ^= 0x01010000u ^ ((uint)key.Length << 8) ^ (uint)outLen;

        // Всё сообщение (ключ дополняется до блока 64 байта и идёт первым).
        int total = (key.Length > 0 ? 64 : 0);
        foreach (var p in parts) total += p.Length;
        var data = new byte[total];
        int off = 0;
        if (key.Length > 0)
        {
            key.CopyTo(data);
            off = 64;
        }
        foreach (var p in parts)
        {
            p.CopyTo(data, off);
            off += p.Length;
        }

        var m = new uint[16];
        ulong counter = 0;
        int pos = 0;
        var block = new byte[64];

        if (data.Length == 0)
        {
            Compress(h, m, block, 0, true);
        }
        while (pos < data.Length)
        {
            int len = Math.Min(64, data.Length - pos);
            Array.Clear(block);
            Array.Copy(data, pos, block, 0, len);
            pos += len;
            counter += (ulong)len;
            Compress(h, m, block, counter, pos >= data.Length);
        }

        var outBytes = new byte[32];
        for (int i = 0; i < 8; i++) BinaryPrimitives.WriteUInt32LittleEndian(outBytes.AsSpan(i * 4), h[i]);
        return outBytes[..outLen];
    }

    public static byte[] Hash256(params byte[][] parts) => Hash(32, ReadOnlySpan<byte>.Empty, parts);

    private static void Compress(uint[] h, uint[] m, byte[] block, ulong t, bool last)
    {
        for (int i = 0; i < 16; i++) m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(i * 4));
        Span<uint> v = stackalloc uint[16];
        for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
        v[12] ^= (uint)t;
        v[13] ^= (uint)(t >> 32);
        if (last) v[14] = ~v[14];

        for (int r = 0; r < 10; r++)
        {
            G(v, 0, 4, 8, 12, m[Sigma[r, 0]], m[Sigma[r, 1]]);
            G(v, 1, 5, 9, 13, m[Sigma[r, 2]], m[Sigma[r, 3]]);
            G(v, 2, 6, 10, 14, m[Sigma[r, 4]], m[Sigma[r, 5]]);
            G(v, 3, 7, 11, 15, m[Sigma[r, 6]], m[Sigma[r, 7]]);
            G(v, 0, 5, 10, 15, m[Sigma[r, 8]], m[Sigma[r, 9]]);
            G(v, 1, 6, 11, 12, m[Sigma[r, 10]], m[Sigma[r, 11]]);
            G(v, 2, 7, 8, 13, m[Sigma[r, 12]], m[Sigma[r, 13]]);
            G(v, 3, 4, 9, 14, m[Sigma[r, 14]], m[Sigma[r, 15]]);
        }
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private static void G(Span<uint> v, int a, int b, int c, int d, uint x, uint y)
    {
        v[a] = v[a] + v[b] + x; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y; v[d] = BitOperations.RotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d]; v[b] = BitOperations.RotateRight(v[b] ^ v[c], 7);
    }

    /// <summary>HMAC-BLAKE2s-256 (блок 64 байта), как в WireGuard.</summary>
    public static byte[] Hmac(byte[] key, params byte[][] parts)
    {
        var k = new byte[64];
        (key.Length > 64 ? Hash256(key) : key).CopyTo(k, 0);
        var ipad = new byte[64];
        var opad = new byte[64];
        for (int i = 0; i < 64; i++) { ipad[i] = (byte)(k[i] ^ 0x36); opad[i] = (byte)(k[i] ^ 0x5c); }
        var inner = Hash256(new[] { ipad }.Concat(parts).ToArray());
        return Hash256(opad, inner);
    }
}
