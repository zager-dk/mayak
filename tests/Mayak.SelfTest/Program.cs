using System.Buffers.Binary;
using System.Text.Json.Nodes;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;
using Mayak.Core.Export;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Mayak.Core.Probe;
using Mayak.Core.Xray;

// Самотест ядра Маяка: dotnet run --project tests/Mayak.SelfTest [папка для примеров]
int failed = 0, passed = 0;

void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

static byte[] Hex(string h) => Convert.FromHexString(h);

Console.WriteLine("X25519 (RFC 7748):");
{
    var k = Hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    var u = Hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    var r = Curve25519.ScalarMult(k, u);
    Check("вектор 1", Convert.ToHexString(r).ToLowerInvariant() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    var alicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var bobPriv = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    var basePoint = new byte[32]; basePoint[0] = 9;
    var alicePub = Curve25519.ScalarMult(alicePriv, basePoint);
    var bobPub = Curve25519.ScalarMult(bobPriv, basePoint);
    Check("публичный ключ Алисы", Convert.ToHexString(alicePub).ToLowerInvariant() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    Check("публичный ключ Боба", Convert.ToHexString(bobPub).ToLowerInvariant() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    var s1 = Curve25519.ScalarMult(alicePriv, bobPub);
    var s2 = Curve25519.ScalarMult(bobPriv, alicePub);
    Check("общий секрет", s1.SequenceEqual(s2) && Convert.ToHexString(s1).ToLowerInvariant() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    var (priv, pub) = Curve25519.GenerateKeyPair();
    Check("генерация пары ключей", Convert.FromBase64String(priv).Length == 32 && Curve25519.PublicKeyFromPrivate(priv) == pub);
}


Console.WriteLine("BLAKE2s / ChaCha20-Poly1305:");
{
    string H(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    var A = System.Text.Encoding.ASCII;
    Check("BLAKE2s(\"abc\")", H(Blake2s.Hash256(A.GetBytes("abc"))) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    Check("BLAKE2s(пусто)", H(Blake2s.Hash256(Array.Empty<byte>())) == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    Check("BLAKE2s 64 байта (ровно блок)", H(Blake2s.Hash256(Enumerable.Range(0, 64).Select(i => (byte)i).ToArray())) == "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e");
    var hw = A.GetBytes(string.Concat(Enumerable.Repeat("hello world", 20)));
    Check("BLAKE2s с ключом, 16 байт", H(Blake2s.Hash(16, A.GetBytes(new string('k', 32)), hw)) == "03e1250dc5725a455670650a2ee16b0c");
    Check("BLAKE2s с коротким ключом", H(Blake2s.Hash(16, A.GetBytes("mac1key"), Enumerable.Range(0, 200).Select(i => (byte)i).ToArray())) == "544a7aefe21239c393f8fc31305e6b1a");

    bool aeadOk = true;
    for (int i = 0; i < 50 && aeadOk; i++)
    {
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var nonce = ChaChaPoly.Nonce((ulong)i * 977);
        var pt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(i * 37);
        var aad = System.Security.Cryptography.RandomNumberGenerator.GetBytes(i % 3 * 17);
        var mine = ChaChaPoly.Seal(key, nonce, pt, aad);
        if (System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            using var reference = new System.Security.Cryptography.ChaCha20Poly1305(key);
            var ct = new byte[pt.Length]; var tag = new byte[16];
            reference.Encrypt(nonce, pt, ct, tag, aad);
            aeadOk &= mine.SequenceEqual(ct.Concat(tag));
        }
        aeadOk &= ChaChaPoly.Open(key, nonce, mine, aad)?.SequenceEqual(pt) == true;
        mine[0] ^= 1;
        aeadOk &= mine.Length == 16 || ChaChaPoly.Open(key, nonce, mine, aad) == null;
    }
    Check($"ChaCha20-Poly1305 совпадает с .NET (эталон доступен: {System.Security.Cryptography.ChaCha20Poly1305.IsSupported})", aeadOk);

    var sig = AwgProbe.Obfuscation.SignaturePacket(AwgParameters.DefaultSpecialJunk1);
    Check("пакет I1 по умолчанию: 2 случайных байта + DNS-ответ", sig.Length == 2 + 42 && sig[2] == 0x85 && sig[3] == 0x80);
}

Console.WriteLine("Параметры AWG:");
{
    bool allOk = true;
    for (int i = 0; i < 500; i++)
    {
        var p = AwgParameters.GenerateV2();
        int s1 = int.Parse(p.S1), s2 = int.Parse(p.S2), s3 = int.Parse(p.S3), s4 = int.Parse(p.S4);
        var sizes = new[] { s1 + 148, s2 + 92, s3 + 64 };
        bool unique = new HashSet<int> { s1, s2, s3, s4 }.Count == 4 && sizes.Distinct().Count() == 3;
        var ranges = new[] { p.H1, p.H2, p.H3, p.H4 }.Select(h => h.Split('-').Select(long.Parse).ToArray()).ToArray();
        bool ordered = ranges.All(r => r[0] >= 5 && r[0] <= r[1] && r[1] <= int.MaxValue)
                       && ranges[0][1] < ranges[1][0] && ranges[1][1] < ranges[2][0] && ranges[2][1] < ranges[3][0];
        if (!unique || !ordered || p.ProtocolVersionString != "2") { allOk = false; Console.WriteLine($"    {p.S1} {p.S2} {p.S3} {p.S4} {p.H1} {p.H2} {p.H3} {p.H4}"); break; }
    }
    Check("AWG 2.0: S1–S4 уникальны, H1–H4 не пересекаются (500 прогонов)", allOk);

    var v3 = AwgParameters.GenerateV3();
    Check("AWG 3.1: версия и ключ защиты заголовков", v3.ProtocolVersionString == "3.1" && Convert.FromBase64String(v3.HeaderProtectionKey).Length == 32);
    Check("AWG 3.1: keepalive диапазоном", v3.PersistentKeepalive == "25-35");
}

Console.WriteLine("Серверный awg0.conf:");
var serverParams = AwgParameters.GenerateV2();
var (srvPriv, srvPub) = Curve25519.GenerateKeyPair();
var psk = Curve25519.GeneratePresharedKey();
{
    var text = "[Interface]\nPrivateKey = " + srvPriv + "\nAddress = 10.8.1.0/24\nListenPort = 41234\n"
               + string.Join("\n", serverParams.ServerInterfaceLines()) + "\n\n"
               + "[Peer]\nPublicKey = AAA=\nPresharedKey = " + psk + "\nAllowedIPs = 10.8.1.1/32\n\n"
               + "[Peer]\nPublicKey = BBB=\nPresharedKey = " + psk + "\nAllowedIPs = 10.8.1.2/32\n\n";
    var conf = AwgConfigFile.Parse(text);
    Check("разбор: два пира", conf.Peers.Count() == 2);
    Check("разбор: порт", conf.GetInterfaceValue("ListenPort") == "41234");
    var back = AwgParameters.FromServerConfig(conf);
    Check("разбор: параметры совпадают (включая # I1)", back.H3 == serverParams.H3 && back.S4 == serverParams.S4 && back.I1 == serverParams.I1);
    Check("удаление пира", conf.RemovePeer("AAA=") && conf.Peers.Single().PublicKey == "BBB=");
    conf.AddPeer("CCC=", psk, "10.8.1.3");
    var reparsed = AwgConfigFile.Parse(conf.ToString());
    Check("добавление пира и повторный разбор", reparsed.Peers.Select(p => p.Ip).SequenceEqual(new[] { "10.8.1.2", "10.8.1.3" }));
}

Console.WriteLine("Выдача IP:");
{
    var ip1 = IpAllocator.Next("10.8.1.0", 24, "10.8.1.0", Array.Empty<string>());
    var ip2 = IpAllocator.Next("10.8.1.0", 24, "10.8.1.0", new[] { "10.8.1.1", "10.8.1.5" });
    var all = Enumerable.Range(1, 254).Select(i => $"10.8.1.{i}").ToList();
    var ip3 = IpAllocator.Next("10.8.1.0", 24, "10.8.1.0", all.Where(a => a != "10.8.1.7"));
    Check("первый адрес 10.8.1.1", ip1 == "10.8.1.1", ip1);
    Check("после максимума: 10.8.1.6", ip2 == "10.8.1.6", ip2);
    Check("дырка, когда конец занят: 10.8.1.7", ip3 == "10.8.1.7", ip3);
    Check("classid tc", IpAllocator.TcClassId("10.8.1.0", 24, "10.8.1.5") == "15");
}

Console.WriteLine("Экспорт:");
var endpoint = new ServerEndpoint
{
    Host = "203.0.113.10",
    Port = 41234,
    ServerPublicKey = srvPub,
    PresharedKey = psk,
    Parameters = serverParams,
};
var (cPriv, cPub) = Curve25519.GenerateKeyPair();
var device = new VpnDevice { Name = "iPhone", Kind = DeviceKind.IPhone, PrivateKey = cPriv, PublicKey = cPub, Ip = "10.8.1.2" };
{
    var conf = ClientConfigFactory.BuildConfFile(endpoint, device, "1.1.1.1", "1.0.0.1");
    var parsed = AwgConfigFile.Parse(conf);
    Check(".conf: ключи и адрес", parsed.GetInterfaceValue("PrivateKey") == cPriv && parsed.GetInterfaceValue("Address") == "10.8.1.2/32");
    Check(".conf: MTU 1280 для iPhone", parsed.GetInterfaceValue("MTU") == "1280");
    Check(".conf: H1 и I1 на месте", parsed.GetInterfaceValue("H1") == serverParams.H1 && parsed.GetInterfaceValue("I1") == serverParams.I1);
    Check(".conf: Endpoint", parsed.Sections[1].Get("Endpoint") == "203.0.113.10:41234");

    device.Kind = DeviceKind.Android;
    var key = ClientConfigFactory.BuildVpnKey(endpoint, device, "1.1.1.1", "1.0.0.1", "Маяк VPN");
    Check("vpn:// префикс и base64url без '='", key.StartsWith("vpn://") && !key.Contains('=') && !key.Contains('+') && key.IndexOf('/', 6) < 0);

    var json = VpnKeyCodec.Decode(key);
    var root = JsonNode.Parse(json)!.AsObject();
    var awg = root["containers"]![0]!["awg"]!.AsObject();
    var last = JsonNode.Parse(awg["last_config"]!.GetValue<string>())!.AsObject();
    Check("JSON: контейнер amnezia-awg2", root["defaultContainer"]!.GetValue<string>() == "amnezia-awg2");
    Check("JSON: описание по-русски", root["description"]!.GetValue<string>() == "Маяк VPN");
    Check("JSON: last_config с ключами клиента", last["client_priv_key"]!.GetValue<string>() == cPriv && last["port"]!.GetValue<int>() == 41234);
    Check("JSON: параметры AWG", awg["H4"]!.GetValue<string>() == serverParams.H4 && last["S3"]!.GetValue<string>() == serverParams.S3);
    Check("JSON: MTU 1280 для Android", last["mtu"]!.GetValue<string>() == "1280");

    // Байты внутри ключа — ровно формат qCompress: 4 байта длины (BE) + zlib (0x78 ..)
    var raw = VpnKeyCodec.Base64UrlDecode(key[6..]);
    uint len = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(0, 4));
    Check("qCompress: длина и заголовок zlib", len == System.Text.Encoding.UTF8.GetByteCount(json) && raw[4] == 0x78);

    var chunks = ClientConfigFactory.BuildAmneziaQrChunks(endpoint, device, "1.1.1.1", "1.0.0.1", "Маяк VPN");
    var assembled = new List<byte>();
    foreach (var c in chunks)
    {
        var b = VpnKeyCodec.Base64UrlDecode(c);
        bool header = BinaryPrimitives.ReadInt16BigEndian(b.AsSpan(0, 2)) == 1984 && b[2] == chunks.Count;
        if (!header) { Check("QR: заголовок", false); break; }
        int l = (int)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(4, 4));
        assembled.AddRange(b.Skip(8).Take(l));
    }
    var fromQr = System.Text.Encoding.UTF8.GetString(VpnKeyCodec.QUncompress(assembled.ToArray()));
    Check($"QR: {chunks.Count} шт., склеиваются обратно в тот же JSON", fromQr == json);

    Check("имя .conf ≤ 15 латиницей", ClientConfigFactory.SuggestFileName("Иван Петров", device, ConfigFormat.AwgConf) is var n && n.Length <= 20 && n.EndsWith(".conf") && n.All(ch => ch < 128), ClientConfigFactory.SuggestFileName("Иван Петров", device, ConfigFormat.AwgConf));

    var outDir = args.Length > 0 ? args[0] : null;
    if (outDir != null)
    {
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "sample.vpn"), key);
        File.WriteAllText(Path.Combine(outDir, "sample.json"), json);
        File.WriteAllText(Path.Combine(outDir, "sample.conf"), conf);
        File.WriteAllLines(Path.Combine(outDir, "sample.qr.txt"), chunks);
        File.WriteAllBytes(Path.Combine(outDir, "sample.qr.png"), QrImages.Png(chunks[0]));
        File.WriteAllText(Path.Combine(outDir, "server_awg0.conf"), "[Interface]\nPrivateKey = " + srvPriv + "\nAddress = 10.8.1.0/24\nListenPort = 41234\n" + string.Join("\n", serverParams.ServerInterfaceLines()) + "\n");
        Console.WriteLine($"Примеры сохранены в {outDir}");
    }
}


Console.WriteLine("Xray:");
{
    var ep = new XrayEndpoint { Port = 443, PublicKey = "PUBKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", ShortId = "a1b2c3d4e5f60718", Sni = "www.googletagmanager.com", XhttpPath = "/abc123", XhttpHost = "www.googletagmanager.com" };
    var id = Guid.NewGuid().ToString();
    var serverJson = XrayConfig.BuildServerJson(ep, "PRIVKEY", new[] { new XrayConfig.Client("owner-uuid", "", ""), new XrayConfig.Client(id, "mayak:dev", "") });
    var parsed = XrayConfig.ParseServerJson(serverJson, ep.PublicKey);
    Check("server.json: разбор порта, SNI, пути, shortId", parsed.Port == 443 && parsed.Sni == ep.Sni && parsed.XhttpPath == "/abc123" && parsed.ShortId == ep.ShortId && parsed.Transport == "xhttp");
    var clients = XrayConfig.ReadClients(serverJson);
    Check("server.json: клиенты и email", clients.Count == 2 && clients[1].Email == "mayak:dev" && clients[0].Email == "");
    var replaced = XrayConfig.ReadClients(XrayConfig.ReplaceClients(serverJson, new[] { new XrayConfig.Client(id, "mayak:dev", "") }));
    Check("server.json: замена клиентов", replaced.Count == 1 && replaced[0].Id == id);

    var client = JsonNode.Parse(XrayConfig.BuildClientJson("203.0.113.10", ep, id))!;
    var ob = client["outbounds"]![0]!;
    Check("клиент: VLESS → адрес, порт, UUID", ob["settings"]!["vnext"]![0]!["address"]!.GetValue<string>() == "203.0.113.10" && ob["settings"]!["vnext"]![0]!["users"]![0]!["id"]!.GetValue<string>() == id);
    Check("клиент: Reality publicKey/shortId/SNI, xhttp", ob["streamSettings"]!["realitySettings"]!["publicKey"]!.GetValue<string>() == ep.PublicKey && ob["streamSettings"]!["network"]!.GetValue<string>() == "xhttp" && ob["streamSettings"]!["xhttpSettings"]!["path"]!.GetValue<string>() == "/abc123");
    Check("клиент: SOCKS на 127.0.0.1:10808", client["inbounds"]![0]!["listen"]!.GetValue<string>() == "127.0.0.1" && client["inbounds"]![0]!["port"]!.GetValue<int>() == 10808);

    var link = XrayConfig.BuildVlessLink("203.0.113.10", ep, id, "Иван iPhone");
    Check("ссылка vless://", link.StartsWith($"vless://{id}@203.0.113.10:443?") && link.Contains("security=reality") && link.Contains("type=xhttp") && link.Contains("path=%2Fabc123") && link.Contains("pbk="));

    var dev = new VpnDevice { Name = "Тест", Kind = DeviceKind.Android, PrivateKey = cPriv, PublicKey = cPub, Ip = "10.8.1.2", XrayId = id };
    var both = JsonNode.Parse(VpnKeyCodec.Decode(ClientConfigFactory.BuildVpnKey(endpoint, dev, "1.1.1.1", "1.0.0.1", "Маяк VPN", ep)))!;
    var containers = both["containers"]!.AsArray();
    var xrayLast = JsonNode.Parse(containers[1]!["xray"]!["last_config"]!.GetValue<string>())!;
    Check("vpn://: два протокола (awg2 + xray)", containers.Count == 2 && containers[1]!["container"]!.GetValue<string>() == "amnezia-xray" && both["defaultContainer"]!.GetValue<string>() == "amnezia-awg2");
    Check("vpn://: last_config Xray с UUID устройства", xrayLast["outbounds"]![0]!["settings"]!["vnext"]![0]!["users"]![0]!["id"]!.GetValue<string>() == id);
    var noXray = JsonNode.Parse(VpnKeyCodec.Decode(ClientConfigFactory.BuildVpnKey(endpoint, dev, "1.1.1.1", "1.0.0.1", "Маяк VPN")))!;
    Check("vpn:// без Xray — один протокол", noXray["containers"]!.AsArray().Count == 1);
}

Console.WriteLine("Скрипты в сборке:");
foreach (var s in new[] { "install_docker.sh", "prepare_host.sh", "Dockerfile", "start.sh", "mayak_tc.sh", "xray.Dockerfile", "xray_start.sh", "xray_configure.sh" })
{
    var text = ScriptLibrary.Load(s, new Dictionary<string, string> { ["SUDO"] = "", ["DOCKERFILE_FOLDER"] = "/x", ["SUBNET_IP"] = "10.8.1.0", ["SUBNET_CIDR"] = "24", ["XRAY_PORT"] = "443", ["XRAY_RELEASE"] = "v1", ["XRAY_SHA256"] = "x" });
    Check(s, text.Length > 50 && !text.Contains("{{") && !text.Contains('\r'));
}

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
return failed == 0 ? 0 : 1;
