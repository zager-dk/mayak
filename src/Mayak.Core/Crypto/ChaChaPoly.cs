using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Mayak.Core.Crypto;

/// <summary>ChaCha20 (RFC 8439), «сырой» поток — нужен для защиты заголовков AWG 3.x.</summary>
public static class ChaCha20
{
    public static void Block(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce, Span<byte> output)
    {
        Span<uint> s = stackalloc uint[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4));
        s[12] = counter;
        for (int i = 0; i < 3; i++) s[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(i * 4));

        Span<uint> x = stackalloc uint[16];
        s.CopyTo(x);
        for (int i = 0; i < 10; i++)
        {
            Q(x, 0, 4, 8, 12); Q(x, 1, 5, 9, 13); Q(x, 2, 6, 10, 14); Q(x, 3, 7, 11, 15);
            Q(x, 0, 5, 10, 15); Q(x, 1, 6, 11, 12); Q(x, 2, 7, 8, 13); Q(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4), x[i] + s[i]);
    }

    private static void Q(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }

    /// <summary>XOR данных с потоком, начиная с байта offset потока (счётчик блоков от initialCounter).</summary>
    public static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint initialCounter, Span<byte> data, int streamOffset = 0)
    {
        Span<byte> ks = stackalloc byte[64];
        int pos = 0;
        long abs = streamOffset;
        while (pos < data.Length)
        {
            uint blockIndex = (uint)(abs / 64);
            int inBlock = (int)(abs % 64);
            Block(key, initialCounter + blockIndex, nonce, ks);
            int n = Math.Min(64 - inBlock, data.Length - pos);
            for (int i = 0; i < n; i++) data[pos + i] ^= ks[inBlock + i];
            pos += n;
            abs += n;
        }
    }
}

/// <summary>Poly1305 (RFC 8439). Через BigInteger: медленно, но пакетов в проверке немного.</summary>
public static class Poly1305
{
    private static readonly BigInteger P = (BigInteger.One << 130) - 5;
    private static readonly BigInteger Mask128 = (BigInteger.One << 128) - 1;

    public static byte[] Mac(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> message)
    {
        var rBytes = key32[..16].ToArray();
        rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
        rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
        var r = new BigInteger(rBytes, isUnsigned: true, isBigEndian: false);
        var s = new BigInteger(key32.Slice(16, 16), isUnsigned: true, isBigEndian: false);

        BigInteger acc = 0;
        Span<byte> block = stackalloc byte[17];
        for (int i = 0; i < message.Length; i += 16)
        {
            int n = Math.Min(16, message.Length - i);
            block.Clear();
            message.Slice(i, n).CopyTo(block);
            block[n] = 1;
            var nInt = new BigInteger(block[..(n + 1)], isUnsigned: true, isBigEndian: false);
            acc = (acc + nInt) * r % P;
        }
        acc = (acc + s) & Mask128;
        var tag = new byte[16];
        var raw = acc.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Copy(raw, tag, Math.Min(16, raw.Length));
        return tag;
    }
}

/// <summary>AEAD ChaCha20-Poly1305 (RFC 8439). Nonce WireGuard: 4 нулевых байта + счётчик (LE).</summary>
public static class ChaChaPoly
{
    public static byte[] Nonce(ulong counter)
    {
        var n = new byte[12];
        BinaryPrimitives.WriteUInt64LittleEndian(n.AsSpan(4), counter);
        return n;
    }

    public static byte[] Seal(byte[] key, byte[] nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var output = new byte[plaintext.Length + 16];
        plaintext.CopyTo(output);
        ChaCha20.Xor(key, nonce, 1, output.AsSpan(0, plaintext.Length));
        var tag = Tag(key, nonce, aad, output.AsSpan(0, plaintext.Length));
        tag.CopyTo(output, plaintext.Length);
        return output;
    }

    /// <summary>Расшифровка; null, если подпись не сошлась.</summary>
    public static byte[]? Open(byte[] key, byte[] nonce, ReadOnlySpan<byte> ciphertextWithTag, ReadOnlySpan<byte> aad)
    {
        if (ciphertextWithTag.Length < 16) return null;
        var ct = ciphertextWithTag[..^16];
        var tag = Tag(key, nonce, aad, ct);
        if (!CryptographicOperations.FixedTimeEquals(tag, ciphertextWithTag[^16..])) return null;
        var plain = ct.ToArray();
        ChaCha20.Xor(key, nonce, 1, plain);
        return plain;
    }

    private static byte[] Tag(byte[] key, byte[] nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> polyKey = stackalloc byte[64];
        ChaCha20.Block(key, 0, nonce, polyKey);

        int Pad(int n) => (16 - n % 16) % 16;
        var mac = new byte[aad.Length + Pad(aad.Length) + ciphertext.Length + Pad(ciphertext.Length) + 16];
        aad.CopyTo(mac);
        int off = aad.Length + Pad(aad.Length);
        ciphertext.CopyTo(mac.AsSpan(off));
        off += ciphertext.Length + Pad(ciphertext.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(mac.AsSpan(off), (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(mac.AsSpan(off + 8), (ulong)ciphertext.Length);
        return Poly1305.Mac(polyKey[..32], mac);
    }
}
