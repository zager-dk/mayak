using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;

namespace Mayak.Core.Probe;

/// <summary>Что нужно, чтобы «прикинуться» клиентом AmneziaWG.</summary>
public sealed class AwgProbeSettings
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string ServerPublicKey { get; set; } = "";
    public string PresharedKey { get; set; } = "";
    public string ClientPrivateKey { get; set; } = "";
    public string ClientIp { get; set; } = "";
    /// <summary>Адрес сервера внутри туннеля (Address из awg0.conf, обычно 10.8.1.0).</summary>
    public string ServerTunnelIp { get; set; } = "";
    public AwgParameters Parameters { get; set; } = new();

    public int PingCount { get; set; } = 400;
    public int PingPayload { get; set; } = 1100;
    public TimeSpan PingInterval { get; set; } = TimeSpan.FromMilliseconds(8);
    /// <summary>Проверить выход в интернет: DNS-запрос к этому серверу через туннель. Пусто — не проверять.</summary>
    public string? DnsServer { get; set; } = "1.1.1.1";
}

public sealed class AwgProbeResult
{
    public bool HandshakeOk { get; set; }
    public double HandshakeMs { get; set; }
    public int HandshakeAttempts { get; set; }
    public int PingSent { get; set; }
    public int PingReceived { get; set; }
    public double RttAvgMs { get; set; }
    public double RttMaxMs { get; set; }
    /// <summary>Сколько байт туда-обратно прошло до последнего успешного ответа.</summary>
    public long BytesConfirmed { get; set; }
    /// <summary>Номер пакета, после которого ответы перестали приходить совсем (признак «заморозки»).</summary>
    public int? StalledAfterPing { get; set; }
    public bool? DnsOk { get; set; }
    public double DnsMs { get; set; }
    public string? Error { get; set; }

    public double LossPercent => PingSent == 0 ? 100 : 100.0 * (PingSent - PingReceived) / PingSent;
}

/// <summary>
/// Мини-клиент AmneziaWG: рукопожатие Noise_IKpsk2 с маскировкой AWG (I1–I5, Jc, S1–S4, H1–H4,
/// защита заголовков 3.x) и серия ping через туннель. Повторяет формат пакетов amneziawg-go.
/// </summary>
public static class AwgProbe
{
    private const string Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    private const string Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    private const string LabelMac1 = "mac1----";
    private const int InitSize = 148, ResponseSize = 92, TransportHeaderSize = 16;

    public static async Task<AwgProbeResult> RunAsync(AwgProbeSettings s, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var result = new AwgProbeResult();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(s.Host, ct);
            var target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.First();
            using var udp = new UdpClient(target.AddressFamily);
            udp.Connect(new IPEndPoint(target, s.Port));

            var p = s.Parameters;
            var hpKey = string.IsNullOrWhiteSpace(p.HeaderProtectionKey) ? null : Convert.FromBase64String(p.HeaderProtectionKey);
            var obf = new Obfuscation(p, hpKey);

            var serverPub = Convert.FromBase64String(s.ServerPublicKey);
            var psk = string.IsNullOrEmpty(s.PresharedKey) ? new byte[32] : Convert.FromBase64String(s.PresharedKey);
            var clientPriv = Convert.FromBase64String(s.ClientPrivateKey);
            var clientPub = Curve25519.ScalarMult(clientPriv, BasePoint());

            Session? session = null;
            for (int attempt = 1; attempt <= 3 && session == null; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                result.HandshakeAttempts = attempt;
                progress?.Report($"AmneziaWG: рукопожатие, попытка {attempt}…");
                var sw = Stopwatch.StartNew();
                var hs = new Handshake(serverPub, clientPriv, clientPub, psk);
                var init = hs.CreateInitiation(obf.PickHeader(p.H1, 1));

                foreach (var pre in obf.PreHandshakePackets())
                    await udp.SendAsync(pre, ct);
                await udp.SendAsync(obf.WrapHandshake(init, Obfuscation.Kind.Init), ct);

                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
                while (DateTime.UtcNow < deadline && session == null)
                {
                    var data = await ReceiveAsync(udp, deadline - DateTime.UtcNow, ct);
                    if (data == null) break;
                    var resp = obf.UnwrapHandshake(data, Obfuscation.Kind.Response);
                    if (resp == null) continue;
                    session = hs.ConsumeResponse(resp);
                }
                if (session != null)
                {
                    result.HandshakeOk = true;
                    result.HandshakeMs = sw.Elapsed.TotalMilliseconds;
                }
            }

            if (session == null)
            {
                result.Error = "Сервер не ответил на рукопожатие. UDP-трафик до порта не доходит или режется по сигнатуре.";
                return result;
            }

            progress?.Report("AmneziaWG: передача данных…");
            await PingSeriesAsync(udp, s, obf, session, result, progress, ct);

            if (!string.IsNullOrEmpty(s.DnsServer))
            {
                progress?.Report("AmneziaWG: выход в интернет (DNS)…");
                await DnsCheckAsync(udp, s, obf, session, result, ct);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            result.Error ??= ex.Message;
        }
        return result;
    }

    // ───────────── Передача данных ─────────────

    private static async Task PingSeriesAsync(UdpClient udp, AwgProbeSettings s, Obfuscation obf, Session session,
        AwgProbeResult result, IProgress<string>? progress, CancellationToken ct)
    {
        var src = IPAddress.Parse(s.ClientIp);
        var dst = IPAddress.Parse(s.ServerTunnelIp);
        ushort icmpId = (ushort)RandomNumberGenerator.GetInt32(1, 65535);
        var sentAt = new DateTime?[s.PingCount];
        var rtts = new List<double>();
        int lastReceivedSeq = -1;
        long bytes = 0;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var receiver = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                var data = await ReceiveAsync(udp, TimeSpan.FromMilliseconds(500), cts.Token);
                if (data == null) continue;
                var plain = obf.UnwrapTransport(data, session);
                if (plain == null || plain.Length < 28) continue;
                if ((plain[0] >> 4) != 4 || plain[9] != 1) continue; // IPv4 + ICMP
                int ihl = (plain[0] & 15) * 4;
                if (plain[ihl] != 0) continue; // echo reply
                ushort id = BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(ihl + 4));
                ushort seq = BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(ihl + 6));
                if (id != icmpId || seq >= sentAt.Length || sentAt[seq] == null) continue;
                lock (rtts)
                {
                    rtts.Add((DateTime.UtcNow - sentAt[seq]!.Value).TotalMilliseconds);
                    sentAt[seq] = null;
                    lastReceivedSeq = Math.Max(lastReceivedSeq, seq);
                    bytes += 2L * plain.Length;
                }
            }
        }, cts.Token);

        for (int seq = 0; seq < s.PingCount; seq++)
        {
            ct.ThrowIfCancellationRequested();
            var packet = Packets.IcmpEcho(src, dst, icmpId, (ushort)seq, s.PingPayload);
            sentAt[seq] = DateTime.UtcNow;
            await udp.SendAsync(obf.WrapTransport(packet, session), ct);
            result.PingSent++;
            if (seq % 50 == 0) progress?.Report($"AmneziaWG: передача данных… {seq}/{s.PingCount}");
            await Task.Delay(s.PingInterval, ct);
        }
        await Task.Delay(1500, ct);
        cts.Cancel();
        try { await receiver; } catch (OperationCanceledException) { }

        lock (rtts)
        {
            result.PingReceived = rtts.Count;
            result.RttAvgMs = rtts.Count > 0 ? rtts.Average() : 0;
            result.RttMaxMs = rtts.Count > 0 ? rtts.Max() : 0;
            result.BytesConfirmed = bytes;
            // «Заморозка»: ответы шли, а последние 20% пакетов остались без ответа.
            if (rtts.Count > 0 && lastReceivedSeq < s.PingCount * 0.8)
                result.StalledAfterPing = lastReceivedSeq + 1;
        }
    }

    private static async Task DnsCheckAsync(UdpClient udp, AwgProbeSettings s, Obfuscation obf, Session session,
        AwgProbeResult result, CancellationToken ct)
    {
        var src = IPAddress.Parse(s.ClientIp);
        var dns = IPAddress.Parse(s.DnsServer!);
        ushort srcPort = (ushort)RandomNumberGenerator.GetInt32(20000, 60000);
        ushort qid = (ushort)RandomNumberGenerator.GetInt32(1, 65535);
        var sw = Stopwatch.StartNew();
        for (int attempt = 0; attempt < 3; attempt++)
        {
            await udp.SendAsync(obf.WrapTransport(Packets.DnsQuery(src, dns, srcPort, qid, "www.google.com"), session), ct);
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (DateTime.UtcNow < deadline)
            {
                var data = await ReceiveAsync(udp, deadline - DateTime.UtcNow, ct);
                if (data == null) break;
                var plain = obf.UnwrapTransport(data, session);
                if (plain == null || plain.Length < 28 || plain[9] != 17) continue;
                int ihl = (plain[0] & 15) * 4;
                ushort dport = BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(ihl + 2));
                if (dport != srcPort || plain.Length < ihl + 8 + 12) continue;
                ushort id = BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(ihl + 8));
                if (id != qid) continue;
                result.DnsOk = true;
                result.DnsMs = sw.Elapsed.TotalMilliseconds;
                return;
            }
        }
        result.DnsOk = false;
    }

    private static async Task<byte[]?> ReceiveAsync(UdpClient udp, TimeSpan timeout, CancellationToken ct)
    {
        if (timeout <= TimeSpan.Zero) return null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var r = await udp.ReceiveAsync(cts.Token);
            return r.Buffer;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (SocketException)
        {
            // ICMP port unreachable и т. п. — считаем, что ответа нет
            await Task.Delay(50, CancellationToken.None);
            return null;
        }
    }

    private static byte[] BasePoint()
    {
        var b = new byte[32];
        b[0] = 9;
        return b;
    }

    // ───────────── Noise IK ─────────────

    internal sealed class Session
    {
        public required byte[] SendKey { get; init; }
        public required byte[] RecvKey { get; init; }
        public required uint LocalIndex { get; init; }
        public required uint RemoteIndex { get; init; }
        public ulong SendCounter;
    }

    internal sealed class Handshake
    {
        private readonly byte[] _serverPub, _clientPriv, _clientPub, _psk;
        private byte[] _hash = Array.Empty<byte>(), _chainKey = Array.Empty<byte>();
        private byte[] _ephPriv = Array.Empty<byte>();
        private uint _localIndex;

        public Handshake(byte[] serverPub, byte[] clientPriv, byte[] clientPub, byte[] psk)
        {
            _serverPub = serverPub;
            _clientPriv = clientPriv;
            _clientPub = clientPub;
            _psk = psk;
        }

        public byte[] CreateInitiation(uint msgType)
        {
            _chainKey = Blake2s.Hash256(Encoding.ASCII.GetBytes(Construction));
            _hash = Blake2s.Hash256(_chainKey, Encoding.ASCII.GetBytes(Identifier));
            _hash = Blake2s.Hash256(_hash, _serverPub);

            _ephPriv = RandomNumberGenerator.GetBytes(32);
            Curve25519.Clamp(_ephPriv);
            var ephPub = Curve25519.ScalarMult(_ephPriv, BasePoint());

            _chainKey = Kdf(_chainKey, ephPub, 1)[0];
            _hash = Blake2s.Hash256(_hash, ephPub);

            var k = Kdf(_chainKey, Curve25519.ScalarMult(_ephPriv, _serverPub), 2);
            _chainKey = k[0];
            var encStatic = ChaChaPoly.Seal(k[1], ChaChaPoly.Nonce(0), _clientPub, _hash);
            _hash = Blake2s.Hash256(_hash, encStatic);

            k = Kdf(_chainKey, Curve25519.ScalarMult(_clientPriv, _serverPub), 2);
            _chainKey = k[0];
            var encTs = ChaChaPoly.Seal(k[1], ChaChaPoly.Nonce(0), Tai64n(), _hash);
            _hash = Blake2s.Hash256(_hash, encTs);

            _localIndex = BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4));

            var msg = new byte[InitSize];
            BinaryPrimitives.WriteUInt32LittleEndian(msg, msgType);
            BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(4), _localIndex);
            ephPub.CopyTo(msg, 8);
            encStatic.CopyTo(msg, 40);
            encTs.CopyTo(msg, 88);
            var mac1Key = Blake2s.Hash256(Encoding.ASCII.GetBytes(LabelMac1), _serverPub);
            Blake2s.Hash(16, mac1Key, msg[..116]).CopyTo(msg, 116);
            // mac2 = нули (cookie нет)
            return msg;
        }

        public Session? ConsumeResponse(byte[] msg)
        {
            if (msg.Length != ResponseSize) return null;
            uint sender = BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(4));
            uint receiver = BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(8));
            if (receiver != _localIndex) return null;
            var ephR = msg.AsSpan(12, 32).ToArray();
            var empty = msg.AsSpan(44, 16).ToArray();

            var hash = Blake2s.Hash256(_hash, ephR);
            var chainKey = Kdf(_chainKey, ephR, 1)[0];
            chainKey = Kdf(chainKey, Curve25519.ScalarMult(_ephPriv, ephR), 1)[0];
            chainKey = Kdf(chainKey, Curve25519.ScalarMult(_clientPriv, ephR), 1)[0];
            var k = Kdf(chainKey, _psk, 3);
            chainKey = k[0];
            hash = Blake2s.Hash256(hash, k[1]);
            if (ChaChaPoly.Open(k[2], ChaChaPoly.Nonce(0), empty, hash) == null) return null;

            var keys = Kdf(chainKey, Array.Empty<byte>(), 2);
            return new Session { SendKey = keys[0], RecvKey = keys[1], LocalIndex = _localIndex, RemoteIndex = sender };
        }

        private static byte[][] Kdf(byte[] key, byte[] input, int n)
        {
            var t0 = Blake2s.Hmac(key, input);
            var t1 = Blake2s.Hmac(t0, new byte[] { 1 });
            if (n == 1) return new[] { t1 };
            var t2 = Blake2s.Hmac(t0, t1, new byte[] { 2 });
            if (n == 2) return new[] { t1, t2 };
            var t3 = Blake2s.Hmac(t0, t2, new byte[] { 3 });
            return new[] { t1, t2, t3 };
        }

        private static byte[] Tai64n()
        {
            var now = DateTimeOffset.UtcNow;
            var b = new byte[12];
            BinaryPrimitives.WriteUInt64BigEndian(b, 0x400000000000000aUL + (ulong)now.ToUnixTimeSeconds());
            uint nanos = (uint)((now.Ticks % TimeSpan.TicksPerSecond) * 100);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8), nanos);
            return b;
        }
    }

    // ───────────── Маскировка AWG ─────────────

    internal sealed class Obfuscation
    {
        public enum Kind { Init, Response, Cookie, Transport }

        private readonly AwgParameters _p;
        private readonly byte[]? _hpKey;
        private readonly int _s1, _s2, _s3, _s4;
        private readonly (uint Lo, uint Hi) _h1, _h2, _h3, _h4;

        public Obfuscation(AwgParameters p, byte[]? hpKey)
        {
            _p = p;
            _hpKey = hpKey;
            _s1 = ParseInt(p.S1); _s2 = ParseInt(p.S2); _s3 = ParseInt(p.S3); _s4 = ParseInt(p.S4);
            _h1 = ParseRange(p.H1, 1); _h2 = ParseRange(p.H2, 2); _h3 = ParseRange(p.H3, 3); _h4 = ParseRange(p.H4, 4);
            if (_hpKey != null && new[] { _s1, _s2, _s3, _s4 }.Any(x => x < 12))
                throw new InvalidOperationException("Для защиты заголовков S1–S4 должны быть не меньше 12.");
        }

        public uint PickHeader(string spec, uint fallback)
        {
            var (lo, hi) = ParseRange(spec, fallback);
            return lo == hi ? lo : (uint)(lo + (ulong)RandomNumberGenerator.GetInt32(0, int.MaxValue) % ((ulong)hi - lo + 1));
        }

        /// <summary>I1–I5 и Jc мусорных пакетов перед каждым рукопожатием.</summary>
        public IEnumerable<byte[]> PreHandshakePackets()
        {
            foreach (var spec in new[] { _p.I1, _p.I2, _p.I3, _p.I4, _p.I5 })
            {
                if (string.IsNullOrWhiteSpace(spec)) continue;
                var pkt = SignaturePacket(spec);
                if (pkt.Length > 0) yield return pkt;
            }
            int jc = ParseInt(_p.Jc), jmin = ParseInt(_p.Jmin), jmax = ParseInt(_p.Jmax);
            for (int i = 0; i < jc; i++)
            {
                int size = jmax > jmin ? jmin + RandomNumberGenerator.GetInt32(0, jmax - jmin) : jmin;
                if (size > 0) yield return RandomNumberGenerator.GetBytes(size);
            }
        }

        public byte[] WrapHandshake(byte[] msg, Kind kind)
        {
            int padding = kind switch { Kind.Init => _s1, Kind.Response => _s2, _ => _s3 };
            var buf = new byte[padding + msg.Length];
            RandomNumberGenerator.Fill(buf.AsSpan(0, padding));
            msg.CopyTo(buf, padding);
            if (_hpKey != null)
                ChaCha20.Xor(_hpKey, buf.AsSpan(0, 12), 0, buf.AsSpan(padding, msg.Length));
            return buf;
        }

        /// <summary>Снимает маскировку с ответа сервера и восстанавливает стандартный тип (2).</summary>
        public byte[]? UnwrapHandshake(byte[] data, Kind kind)
        {
            int padding = kind == Kind.Response ? _s2 : _s3;
            int size = kind == Kind.Response ? ResponseSize : 64;
            var range = kind == Kind.Response ? _h2 : _h3;
            if (data.Length < padding + size || data.Length < 12) return null;
            var msg = data.AsSpan(padding, size).ToArray();
            if (_hpKey != null)
                ChaCha20.Xor(_hpKey, data.AsSpan(0, 12), 0, msg);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(msg);
            if (type < range.Lo || type > range.Hi) return null;
            return msg;
        }

        public byte[] WrapTransport(byte[] ipPacket, Session session)
        {
            int padLen = (16 - ipPacket.Length % 16) % 16;
            var plain = new byte[ipPacket.Length + padLen];
            ipPacket.CopyTo(plain, 0);

            ulong counter = session.SendCounter++;
            var sealedData = ChaChaPoly.Seal(session.SendKey, ChaChaPoly.Nonce(counter), plain, ReadOnlySpan<byte>.Empty);

            var buf = new byte[_s4 + TransportHeaderSize + sealedData.Length];
            RandomNumberGenerator.Fill(buf.AsSpan(0, _s4));
            var header = buf.AsSpan(_s4, TransportHeaderSize);
            BinaryPrimitives.WriteUInt32LittleEndian(header, PickHeader(_p.H4, 4));
            BinaryPrimitives.WriteUInt32LittleEndian(header[4..], session.RemoteIndex);
            BinaryPrimitives.WriteUInt64LittleEndian(header[8..], counter);
            sealedData.CopyTo(buf, _s4 + TransportHeaderSize);
            if (_hpKey != null)
                ChaCha20.Xor(_hpKey, buf.AsSpan(0, 12), 0, header);
            return buf;
        }

        public byte[]? UnwrapTransport(byte[] data, Session session)
        {
            if (data.Length < _s4 + TransportHeaderSize + 16 || data.Length < 12) return null;
            var header = data.AsSpan(_s4, TransportHeaderSize).ToArray();
            if (_hpKey != null)
                ChaCha20.Xor(_hpKey, data.AsSpan(0, 12), 0, header);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(header);
            if (type < _h4.Lo || type > _h4.Hi) return null;
            uint receiver = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
            if (receiver != session.LocalIndex) return null;
            ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8));
            return ChaChaPoly.Open(session.RecvKey, ChaChaPoly.Nonce(counter), data.AsSpan(_s4 + TransportHeaderSize), ReadOnlySpan<byte>.Empty);
        }

        /// <summary>Пакет-«подпись» I1–I5: теги &lt;b 0x..&gt;, &lt;r N&gt;, &lt;rc N&gt;, &lt;rd N&gt;, &lt;t&gt;.</summary>
        internal static byte[] SignaturePacket(string spec)
        {
            var output = new List<byte>();
            int pos = 0;
            while (true)
            {
                int start = spec.IndexOf('<', pos);
                if (start < 0) break;
                int end = spec.IndexOf('>', start);
                if (end < 0) break;
                var parts = spec[(start + 1)..end].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                pos = end + 1;
                if (parts.Length == 0) continue;
                var arg = parts.Length > 1 ? parts[1] : "";
                switch (parts[0])
                {
                    case "b":
                        var hex = arg.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? arg[2..] : arg;
                        output.AddRange(Convert.FromHexString(hex));
                        break;
                    case "r":
                        output.AddRange(RandomNumberGenerator.GetBytes(int.Parse(arg)));
                        break;
                    case "rc":
                        const string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        for (int i = 0; i < int.Parse(arg); i++) output.Add((byte)letters[RandomNumberGenerator.GetInt32(letters.Length)]);
                        break;
                    case "rd":
                        for (int i = 0; i < int.Parse(arg); i++) output.Add((byte)('0' + RandomNumberGenerator.GetInt32(10)));
                        break;
                    case "t":
                        var t = new byte[4];
                        BinaryPrimitives.WriteUInt32BigEndian(t, (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        output.AddRange(t);
                        break;
                }
            }
            return output.ToArray();
        }

        private static int ParseInt(string s) => int.TryParse(s, out var v) ? v : 0;

        private static (uint Lo, uint Hi) ParseRange(string s, uint fallback)
        {
            if (string.IsNullOrWhiteSpace(s)) return (fallback, fallback);
            var parts = s.Split('-', 2);
            uint lo = uint.Parse(parts[0].Trim());
            uint hi = parts.Length > 1 ? uint.Parse(parts[1].Trim()) : lo;
            return (lo, hi);
        }
    }

    // ───────────── Пакеты IPv4 ─────────────

    internal static class Packets
    {
        public static byte[] IcmpEcho(IPAddress src, IPAddress dst, ushort id, ushort seq, int payloadSize)
        {
            var icmp = new byte[8 + payloadSize];
            icmp[0] = 8; // echo request
            BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(4), id);
            BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(6), seq);
            RandomNumberGenerator.Fill(icmp.AsSpan(8));
            BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(2), Checksum(icmp));
            return Ipv4(src, dst, 1, icmp);
        }

        public static byte[] DnsQuery(IPAddress src, IPAddress dst, ushort srcPort, ushort qid, string name)
        {
            var q = new List<byte>();
            var head = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(head, qid);
            head[2] = 0x01; // RD
            head[5] = 1;    // QDCOUNT
            q.AddRange(head);
            foreach (var label in name.Split('.'))
            {
                q.Add((byte)label.Length);
                q.AddRange(Encoding.ASCII.GetBytes(label));
            }
            q.Add(0);
            q.AddRange(new byte[] { 0, 1, 0, 1 }); // A, IN

            var udpBytes = new byte[8 + q.Count];
            BinaryPrimitives.WriteUInt16BigEndian(udpBytes, srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(udpBytes.AsSpan(2), 53);
            BinaryPrimitives.WriteUInt16BigEndian(udpBytes.AsSpan(4), (ushort)udpBytes.Length);
            q.ToArray().CopyTo(udpBytes, 8);
            // контрольная сумма UDP в IPv4 необязательна (0)
            return Ipv4(src, dst, 17, udpBytes);
        }

        private static byte[] Ipv4(IPAddress src, IPAddress dst, byte proto, byte[] payload)
        {
            var pkt = new byte[20 + payload.Length];
            pkt[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), (ushort)pkt.Length);
            BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(4), (ushort)RandomNumberGenerator.GetInt32(0, 65535));
            pkt[6] = 0x40; // DF
            pkt[8] = 64;
            pkt[9] = proto;
            src.GetAddressBytes().CopyTo(pkt, 12);
            dst.GetAddressBytes().CopyTo(pkt, 16);
            BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(10), Checksum(pkt.AsSpan(0, 20)));
            payload.CopyTo(pkt, 20);
            return pkt;
        }

        private static ushort Checksum(ReadOnlySpan<byte> data)
        {
            uint sum = 0;
            for (int i = 0; i + 1 < data.Length; i += 2) sum += (uint)(data[i] << 8 | data[i + 1]);
            if (data.Length % 2 == 1) sum += (uint)(data[^1] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
