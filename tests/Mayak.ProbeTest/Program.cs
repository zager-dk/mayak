using System.Diagnostics;
using System.Text;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;
using Mayak.Core.Probe;

// Проверка AwgProbe против настоящего amneziawg-go (Linux, root, /dev/net/tun).
// dotnet run --project tests/Mayak.ProbeTest -- <путь к amneziawg-go>
var binary = args.ElementAtOrDefault(0) ?? "/root/amneziawg-go";
var lab = Path.Combine(AppContext.BaseDirectory, "lab", "awg_lab.py");
if (!File.Exists(lab)) lab = Path.GetFullPath(Path.Combine("tests", "Mayak.ProbeTest", "lab", "awg_lab.py"));

int failed = 0;
foreach (var version in new[] { AwgProtocolVersion.V2, AwgProtocolVersion.V3 })
{
    Console.WriteLine($"=== AmneziaWG {(version == AwgProtocolVersion.V3 ? "3.1" : "2.0")} ===");
    var p = AwgParameters.Generate(version);
    var (srvPriv, srvPub) = Curve25519.GenerateKeyPair();
    var (cliPriv, cliPub) = Curve25519.GenerateKeyPair();
    var psk = Curve25519.GeneratePresharedKey();
    int port = 51900 + (int)version;
    var iface = $"awgt{(int)version}";

    string Hex(string b64) => Convert.ToHexString(Convert.FromBase64String(b64)).ToLowerInvariant();
    var uapi = new StringBuilder();
    uapi.Append("set=1\n");
    uapi.Append($"private_key={Hex(srvPriv)}\nlisten_port={port}\n");
    void Kv(string k, string v) { if (!string.IsNullOrWhiteSpace(v)) uapi.Append($"{k}={v}\n"); }
    Kv("jc", p.Jc); Kv("jmin", p.Jmin); Kv("jmax", p.Jmax);
    Kv("s1", p.S1); Kv("s2", p.S2); Kv("s3", p.S3); Kv("s4", p.S4);
    Kv("h1", p.H1); Kv("h2", p.H2); Kv("h3", p.H3); Kv("h4", p.H4);
    if (p.IsV3)
    {
        Kv("header_protection_key", Hex(p.HeaderProtectionKey));
        Kv("random_trailers", p.RandomTrailers == "on" ? "true" : "false");
        Kv("disable_cookies", p.DisableCookies == "on" ? "true" : "false");
    }
    uapi.Append($"public_key={Hex(cliPub)}\npreshared_key={Hex(psk)}\nallowed_ip=10.9.{(int)version}.5/32\n\n");
    var uapiFile = Path.GetTempFileName();
    File.WriteAllText(uapiFile, uapi.ToString());

    var psi = new ProcessStartInfo("python3", $"{lab} {binary} {iface} 10.9.{(int)version}.0/24 {uapiFile}")
    {
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    using var labProc = Process.Start(psi)!;
    var ready = labProc.StandardOutput.ReadLine();
    if (ready != "READY")
    {
        Console.WriteLine("  стенд не поднялся: " + ready);
        failed++;
        continue;
    }

    var result = await AwgProbe.RunAsync(new AwgProbeSettings
    {
        Host = "127.0.0.1",
        Port = port,
        ServerPublicKey = srvPub,
        PresharedKey = psk,
        ClientPrivateKey = cliPriv,
        ClientIp = $"10.9.{(int)version}.5",
        ServerTunnelIp = $"10.9.{(int)version}.0",
        Parameters = p,
        PingCount = 200,
        DnsServer = null,
    }, new Progress<string>(m => Console.WriteLine("  · " + m)));

    Console.WriteLine($"  рукопожатие: {result.HandshakeOk} за {result.HandshakeMs:0} мс (попыток {result.HandshakeAttempts})");
    Console.WriteLine($"  ping: {result.PingReceived}/{result.PingSent}, потери {result.LossPercent:0.#}%, RTT {result.RttAvgMs:0.0} мс, байт {result.BytesConfirmed}");
    if (result.Error != null) Console.WriteLine("  ошибка: " + result.Error);
    bool ok = result.HandshakeOk && result.PingReceived >= result.PingSent * 0.95;
    Console.WriteLine(ok ? "  OK" : "  FAIL");
    if (!ok) failed++;

    // Неверный ключ сервера — проверка должна честно провалиться
    var bad = await AwgProbe.RunAsync(new AwgProbeSettings
    {
        Host = "127.0.0.1", Port = port, ServerPublicKey = Curve25519.GenerateKeyPair().PublicKey, PresharedKey = psk,
        ClientPrivateKey = cliPriv, ClientIp = $"10.9.{(int)version}.5", ServerTunnelIp = $"10.9.{(int)version}.0",
        Parameters = p, PingCount = 5, DnsServer = null,
    });
    Console.WriteLine(bad.HandshakeOk ? "  FAIL: рукопожатие с чужим ключом прошло" : "  OK    чужой ключ отвергнут");
    if (bad.HandshakeOk) failed++;

    labProc.StandardInput.Close();
    if (!labProc.WaitForExit(5000)) labProc.Kill(entireProcessTree: true);
}

Console.WriteLine(failed == 0 ? "Итого: всё OK" : $"Итого: ошибок {failed}");
return failed == 0 ? 0 : 1;
