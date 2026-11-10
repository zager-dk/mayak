using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Api.Services;
using Mayak.Core.Agent;
using Mayak.Core.Models;
using Mayak.Core.Xray;

// Изолированный тест (без БД и сети): отпечаток Xray для клиентов не входит в identity выхода.
// Инцидент 10.11.2026: правка Fingerprint в XrayJson перевела выходы в failed.
var failed = 0;
var passed = 0;
void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (ok) passed++; else failed++;
}

// Xray так, как его видит агент: ParseServerJson не знает отпечатка и ставит значение по умолчанию.
var serverXray = new XrayEndpoint
{
    Port = 443, PublicKey = "test-public-key", ShortId = "0123abcd", Sni = "www.example.org",
    Transport = "xhttp", XhttpPath = "/p", XhttpHost = "h.example.org", XhttpMode = "auto",
};
ClusterIdentity Cluster(string? clientFingerprint) => new()
{
    AwgJson = JsonSerializer.Serialize(new ServerEndpoint()),
    AwgServerPrivateKey = "awg-test-private",
    XrayJson = JsonSerializer.Serialize(serverXray),
    XrayPrivateKey = "xray-test-private",
    XrayClientFingerprint = clientFingerprint,
};
AgentIdentity AgentHello() => new()
{
    Awg = new ServerEndpoint(), AwgServerPrivateKey = "awg-test-private",
    Xray = JsonSerializer.Deserialize<XrayEndpoint>(JsonSerializer.Serialize(serverXray)), XrayPrivateKey = "xray-test-private",
};

var plain = Cluster(null);
var firefox = Cluster("firefox");

Check("IdentityHash не меняется от отпечатка для клиентов",
    ProvisioningPlanner.IdentityHash(plain) == ProvisioningPlanner.IdentityHash(firefox));
Check("hello агента (отпечаток по умолчанию) совпадает с кластером при firefox для клиентов",
    ClusterService.IdentityMatches(firefox, AgentHello()));
Check("XrayOf (identity) оставляет отпечаток сервера", ClusterService.XrayOf(firefox)!.Fingerprint == "chrome");
Check("ClientXrayOf выдаёт firefox", ClusterService.ClientXrayOf(firefox)!.Fingerprint == "firefox");
Check("без поля клиенты по умолчанию получают firefox", ClusterService.ClientXrayOf(plain)!.Fingerprint == "firefox");
Check("явный chrome в админке выдаётся как chrome", ClusterService.ClientXrayOf(Cluster("chrome"))!.Fingerprint == "chrome");
var sameExceptFp = ClusterService.ClientXrayOf(plain)!; sameExceptFp.Fingerprint = "chrome";
Check("кроме отпечатка ClientXrayOf совпадает с XrayOf",
    JsonSerializer.Serialize(sameExceptFp) == JsonSerializer.Serialize(ClusterService.XrayOf(plain)));

var link = XrayConfig.BuildVlessLink("exit.example.org", ClusterService.ClientXrayOf(firefox)!, Guid.NewGuid().ToString(), "Маяк · тест");
Check("ссылка vless:// содержит fp=firefox", link.Contains("fp=firefox") && !link.Contains("fp=chrome"));
Check("ссылка сохраняет путь и host XHTTP", link.Contains("path=%2Fp") || link.Contains("path=/p"));
var native = XrayConfig.BuildClientJson("exit.example.org", ClusterService.ClientXrayOf(firefox)!, Guid.NewGuid().ToString());
Check("нативный конфиг содержит fingerprint firefox", native.Contains("\"fingerprint\": \"firefox\"") || native.Contains("\"fingerprint\":\"firefox\""));

var bogus = Cluster("chrome\"&x=1");
Check("недопустимое значение в базе заменяется значением по умолчанию", ClusterService.ClientXrayOf(bogus)!.Fingerprint == "firefox");
Check("список допустимых не принимает регистр и пустое",
    !ClusterService.IsClientFingerprint("Firefox") && !ClusterService.IsClientFingerprint("") && ClusterService.IsClientFingerprint("safari"));

// Контроль: правка самого XrayJson (как утром 10.11) действительно ломает identity — ради этого поле и вынесено.
var edited = Cluster(null);
edited.XrayJson = edited.XrayJson!.Replace("\"Fingerprint\":\"chrome\"", "\"Fingerprint\":\"firefox\"");
Check("контроль: правка XrayJson меняет IdentityHash", ProvisioningPlanner.IdentityHash(edited) != ProvisioningPlanner.IdentityHash(plain));
Check("контроль: правка XrayJson ломает сверку с hello агента", !ClusterService.IdentityMatches(edited, AgentHello()));

// Название и DNS: правка в админке не снимает подтверждение выходов.
var renamed = Cluster(null);
renamed.Title = "Другое название"; renamed.Dns1 = "9.9.9.9"; renamed.Dns2 = "149.112.112.112";
Check("название и DNS не входят в IdentityHash", ProvisioningPlanner.IdentityHash(renamed) == ProvisioningPlanner.IdentityHash(plain));
Check("hello агента со старыми названием и DNS совпадает после правки", ClusterService.IdentityMatches(renamed, AgentHello()));
Check("сохранённый хэш новой формулы принимается после правки названия и DNS",
    ProvisioningPlanner.IdentityHashMatches(ProvisioningPlanner.IdentityHash(plain), renamed));
Check("хэш старой формулы (до выпуска) принимается, пока название и DNS прежние",
    ProvisioningPlanner.IdentityHashMatches(ProvisioningPlanner.LegacyIdentityHash(plain), plain));
Check("старая и новая формулы различаются (нет случайного совпадения)",
    ProvisioningPlanner.LegacyIdentityHash(plain) != ProvisioningPlanner.IdentityHash(plain));
Check("пустой сохранённый хэш не принимается", !ProvisioningPlanner.IdentityHashMatches(null, plain));
var rekeyed = Cluster(null); rekeyed.XrayPrivateKey = "other-private";
Check("смена ключа по-прежнему снимает подтверждение",
    !ProvisioningPlanner.IdentityHashMatches(ProvisioningPlanner.IdentityHash(plain), rekeyed) && !ClusterService.IdentityMatches(rekeyed, AgentHello()));

// Формула старого хэша должна совпадать с SQL, которым 10.11.2026 восстанавливали выходы (sha256 строк через \n).
var sqlEquivalent = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
    string.Join('\n', plain.AwgJson, plain.AwgServerPrivateKey, plain.XrayJson, plain.XrayPrivateKey, plain.Dns1, plain.Dns2, plain.Title)))).ToLowerInvariant();
Check("старая формула совпадает с SQL-восстановлением", sqlEquivalent == ProvisioningPlanner.LegacyIdentityHash(plain));

// Пути Xray в ответе допуска (mayak_paths=1).
Check("без поля mayak_paths пути не запрашиваются", !Mayak.Api.Gateway.XrayPathCatalog.IsRequested(new System.Text.Json.Nodes.JsonObject()));
Check("mayak_paths=1 запрашивает пути", Mayak.Api.Gateway.XrayPathCatalog.IsRequested(System.Text.Json.Nodes.JsonNode.Parse("{\"mayak_paths\":1}")!.AsObject()));
Check("mayak_paths=\"1\" и 2 не принимаются",
    !Mayak.Api.Gateway.XrayPathCatalog.IsRequested(System.Text.Json.Nodes.JsonNode.Parse("{\"mayak_paths\":\"1\"}")!.AsObject()) &&
    !Mayak.Api.Gateway.XrayPathCatalog.IsRequested(System.Text.Json.Nodes.JsonNode.Parse("{\"mayak_paths\":2}")!.AsObject()));
Check("порядок отпечатков: firefox, safari, chrome",
    string.Join(",", Mayak.Api.Gateway.XrayPathCatalog.Fingerprints(plain)) == "firefox,safari,chrome");
Check("выбранный в админке safari идёт первым без повторов",
    string.Join(",", Mayak.Api.Gateway.XrayPathCatalog.Fingerprints(Cluster("safari"))) == "safari,chrome,random");
var device = new Device { Name = "тест", XrayId = Guid.NewGuid().ToString() };
var built = Mayak.Api.Gateway.XrayPathCatalog.Build(plain, "exit.example.org", device)!;
var paths = built["paths"]!.AsArray();
bool pathsOk = paths.Count == 3 && built["schema"]!.GetValue<int>() == 1;
foreach (var p in paths)
{
    var root = System.Text.Json.Nodes.JsonNode.Parse(Mayak.Core.Export.VpnKeyCodec.Decode(p!["config"]!.GetValue<string>()))!;
    var x = root["containers"]![0]!["xray"]!;
    pathsOk &= root["hostName"]!.GetValue<string>() == "exit.example.org" && root["defaultContainer"]!.GetValue<string>() == "amnezia-xray"
        && x["xray_fingerprint"]!.GetValue<string>() == p["fingerprint"]!.GetValue<string>()
        && x["xhttp"]!["xhttp_path"]!.GetValue<string>() == "/p" && x["xhttp"]!["xhttp_host"]!.GetValue<string>() == "h.example.org"
        && x["xhttp"]!["xhttp_mode"]!.GetValue<string>() == "auto"
        && x["last_config"]!.GetValue<string>().Contains(device.XrayId) && x["last_config"]!.GetValue<string>().Contains(p["fingerprint"]!.GetValue<string>());
}
Check("3 пути Xray: тот же хост, путь/host/режим XHTTP, свой отпечаток, UUID устройства", pathsOk);
Check("без XrayId пути не строятся", Mayak.Api.Gateway.XrayPathCatalog.Build(plain, "exit.example.org", new Device { Name = "x" }) == null);
var noXray = Cluster(null); noXray.XrayJson = null;
Check("без Xray на кластере пути не строятся", Mayak.Api.Gateway.XrayPathCatalog.Build(noXray, "exit.example.org", device) == null);

Console.WriteLine($"passed={passed} failed={failed}");
return failed == 0 ? 0 : 1;
