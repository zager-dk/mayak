using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Mayak.Core.Gateway;

// Совместимость шлюза Маяка с настоящим клиентом Amnezia (libagw).
// Запуск: dotnet run --project tests/Mayak.GatewayTest -- <путь к agwprobe>
int failed = 0, passed = 0;
void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

var (priv, pub) = GatewayCrypto.GenerateKeyPair();
using var rsa = RSA.Create();
rsa.ImportFromPem(priv);
using var rsaPub = RSA.Create();
rsaPub.ImportFromPem(pub);

Console.WriteLine("Конверт C# ↔ C#:");
{
    var (body, session) = GatewayCrypto.SealRequest("{\"a\":\"привет\"}", rsaPub);
    var (json, serverSession) = GatewayCrypto.OpenRequest(body, rsa);
    Check("запрос расшифрован", json == "{\"a\":\"привет\"}");
    var resp = GatewayCrypto.SealResponse("{\"ok\":true}", serverSession);
    Check("ответ расшифрован клиентом", GatewayCrypto.OpenResponse(resp, session) == "{\"ok\":true}");
    using var other = RSA.Create(2048);
    bool refused = false;
    try { GatewayCrypto.OpenRequest(body, other); } catch (GatewayCryptoException) { refused = true; }
    Check("чужой ключ не открывает запрос", refused);
}

var probe = args.ElementAtOrDefault(0);
if (probe == null || !File.Exists(probe))
{
    Console.WriteLine("agwprobe не указан — проверка с настоящим клиентом пропущена");
}
else
{
    Console.WriteLine("Настоящий клиент libagw → сервер Маяка:");
    var l = new TcpListener(IPAddress.Loopback, 0);
    l.Start();
    int port = ((IPEndPoint)l.LocalEndpoint).Port;
    l.Stop();
    using var http = new HttpListener();
    http.Prefixes.Add($"http://127.0.0.1:{port}/");
    http.Start();
    string? seenPath = null, seenJson = null;
    var serve = Task.Run(async () =>
    {
        while (http.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await http.GetContextAsync(); } catch { break; }
            using var reader = new StreamReader(ctx.Request.InputStream);
            var raw = await reader.ReadToEndAsync();
            seenPath = ctx.Request.Url!.AbsolutePath;
            try
            {
                var (json, s) = GatewayCrypto.OpenRequest(raw, rsa);
                seenJson = json;
                var answer = new JsonObject { ["echo"] = JsonNode.Parse(json), ["path"] = seenPath, ["status"] = "ok" };
                var bytes = GatewayCrypto.SealResponse(answer.ToJsonString(), s);
                ctx.Response.StatusCode = 200;
                await ctx.Response.OutputStream.WriteAsync(bytes);
            }
            catch (GatewayCryptoException ex)
            {
                ctx.Response.StatusCode = 400;
                var bytes = System.Text.Encoding.UTF8.GetBytes("{\"error\":\"" + ex.Message + "\"}");
                await ctx.Response.OutputStream.WriteAsync(bytes);
            }
            ctx.Response.Close();
        }
    });

    var pemFile = Path.GetTempFileName();
    File.WriteAllText(pemFile, pub);
    (int code, string output) Run(string pemPath)
    {
        var psi = new ProcessStartInfo(probe) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { $"http://127.0.0.1:{port}/", pemPath, "v1/config", "{\"public_key\":\"abc=\",\"service_type\":\"mayak\",\"name\":\"Тест\"}" })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, o);
    }

    var (rc, outp) = Run(pemFile);
    Check("клиент Amnezia принял ответ сервера Маяка", rc == 0 && outp.StartsWith("OK"), outp);
    Check("сервер получил путь и тело запроса", seenPath == "/v1/config" && seenJson?.Contains("\"name\":\"Тест\"") == true, $"{seenPath} {seenJson}");
    var echoed = outp.StartsWith("OK ") ? JsonNode.Parse(outp[3..]) : null;
    Check("ответ расшифрован клиентом как есть", echoed?["status"]?.GetValue<string>() == "ok" && echoed?["echo"]?["public_key"]?.GetValue<string>() == "abc=", outp);

    var wrongPem = Path.GetTempFileName();
    File.WriteAllText(wrongPem, GatewayCrypto.GenerateKeyPair().PublicPem);
    var (rc2, out2) = Run(wrongPem);
    Check("клиент с чужим ключом не получает данных", rc2 != 0, out2);

    http.Stop();
    File.Delete(pemFile);
    File.Delete(wrongPem);
}

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
return failed == 0 ? 0 : 1;
