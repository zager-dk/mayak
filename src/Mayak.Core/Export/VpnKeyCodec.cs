using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Mayak.Core.Export;

/// <summary>
/// Формат ключа vpn:// приложения AmneziaVPN:
/// vpn:// + base64url( qCompress(JSON) ), без «=» в конце.
/// qCompress = 4 байта длины исходных данных (big-endian) + поток zlib.
/// </summary>
public static class VpnKeyCodec
{
    public const string Prefix = "vpn://";

    /// <summary>Аналог Qt qCompress.</summary>
    public static byte[] QCompress(byte[] data)
    {
        using var ms = new MemoryStream();
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)data.Length);
        ms.Write(len);
        using (var z = new ZLibStream(ms, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            z.Write(data, 0, data.Length);
        }
        return ms.ToArray();
    }

    /// <summary>Аналог Qt qUncompress.</summary>
    public static byte[] QUncompress(byte[] data)
    {
        if (data.Length < 4) throw new InvalidDataException("Слишком короткие данные");
        uint expected = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(0, 4));
        using var input = new MemoryStream(data, 4, data.Length - 4);
        using var z = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        z.CopyTo(output);
        var result = output.ToArray();
        if (result.Length != expected)
            throw new InvalidDataException($"Длина не совпадает: {result.Length} вместо {expected}");
        return result;
    }

    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string text)
    {
        var s = text.Trim().Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public static string Encode(string json) => Prefix + Base64UrlEncode(QCompress(Encoding.UTF8.GetBytes(json)));

    public static string Decode(string key)
    {
        var body = key.Trim();
        if (body.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) body = body[Prefix.Length..];
        return Encoding.UTF8.GetString(QUncompress(Base64UrlDecode(body)));
    }

    /// <summary>
    /// Нарезка для QR-кодов в формате Amnezia (qrCodeUtils::generateQrCodeImageSeries):
    /// QDataStream: qint16 1984, quint8 всего, quint8 номер, QByteArray (quint32 длина + байты),
    /// затем base64url без «=». Кусок — до 850 байт сжатых данных.
    /// </summary>
    public static IReadOnlyList<string> AmneziaQrChunks(string json)
    {
        const int chunkSize = 850;
        const short magic = 1984;
        var compressed = QCompress(Encoding.UTF8.GetBytes(json));
        int count = (int)Math.Ceiling(compressed.Length / (double)chunkSize);
        var result = new List<string>(count);
        for (int i = 0, index = 0; i < compressed.Length; i += chunkSize, index++)
        {
            int len = Math.Min(chunkSize, compressed.Length - i);
            var buf = new byte[2 + 1 + 1 + 4 + len];
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(0, 2), magic);
            buf[2] = (byte)count;
            buf[3] = (byte)index;
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(4, 4), (uint)len);
            Array.Copy(compressed, i, buf, 8, len);
            result.Add(Base64UrlEncode(buf));
        }
        return result;
    }
}
