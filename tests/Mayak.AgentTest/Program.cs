using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Mayak.Agent;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Awg;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

// Сквозной тест: API (PostgreSQL) ↔ агент ↔ сервер на стенде с заглушками docker/awg/tc.
// Запуск (заглушки в PATH): PATH=/root/fakebin:$PATH dotnet run --project tests/Mayak.AgentTest
// Не запускайте на боевом сервере: тест переустанавливает VPN в локальной системе.
int failed = 0, passed = 0;
void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

var pg = args.ElementAtOrDefault(0) ?? "Host=127.0.0.1;Port=55432;Username=postgres";
var dbName = "mayak_agent_" + Guid.NewGuid().ToString("N")[..8];
Environment.SetEnvironmentVariable("MAYAK_ConnectionStrings__Db", $"{pg};Database={dbName}");
Environment.SetEnvironmentVariable("MAYAK_Telegram__Polling", "false");
Environment.SetEnvironmentVariable("MAYAK_Logging__LogLevel__Default", "Warning");

var log = new List<string>();
void Log(string m) { lock (log) log.Add(m); }

Console.WriteLine("Сервер, как его оставил Маяк для Windows:");
using (var shell = new LocalShell("/root/.mayak_agent_tmp"))
{
    var win = new MayakServer(shell, "127.0.0.1");
    win.Connect();
    win.Install(new InstallOptions { Port = 41234, Version = AwgProtocolVersion.V2 }, reinstall: win.GetState() is ServerState.Running or ServerState.Stopped);
    var snap = win.Load();
    var ivan = new VpnUser { Name = "Иван" };
    snap.Db.Users.Add(ivan);
    win.Save(snap);
    win.AddDevice(snap, ivan, "iPhone", DeviceKind.IPhone, 35, 35);
    win.AddDevice(snap, ivan, "Ноутбук", DeviceKind.Windows, 50, 0);
    win.EnsureProbe(win.Load());
    Check("стенд: VPN установлен, два устройства Ивана и служебная учётка", win.Load().PeersOnServer.Count == 3);
}

await using var factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b => b.UseContentRoot(AppContext.BaseDirectory));
var api = factory.CreateClient();

string ownerToken = Tokens.New();
using (var scope = factory.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
    var owner = new Account { Name = "Владелец", Role = Roles.Owner, TelegramId = 1 };
    db.Accounts.Add(owner);
    db.Sessions.Add(new Session { TokenHash = Tokens.Hash(ownerToken), AccountId = owner.Id });
    await db.SaveChangesAsync();
}
var admin = factory.CreateClient();
admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);

AgentRunner AgentFor(string token)
{
    var http = factory.CreateClient();
    return new AgentRunner(new AgentConfig { Api = "http://localhost", Token = token, PublicHost = "45.131.185.211" }, http, () => new LocalShell("/root/.mayak_agent_tmp"), Log);
}
string Conf() => File.ReadAllText(MayakServer.ConfPath);
int PeerCount() => Conf().Split('\n').Count(l => l.Trim() == "[Peer]");

Console.WriteLine("Знакомство агента с API:");
var created = await (await admin.PostAsJsonAsync("/api/admin/servers", new { name = "Хельсинки", role = "exit", host = "45.131.185.211" })).Content.ReadFromJsonAsync<JsonNode>();
var agent = AgentFor(created!["agentToken"]!.GetValue<string>());
await agent.CycleAsync(CancellationToken.None);
Check("агент на связи как выход", agent.Role == "exit", string.Join(" | ", log));
var cluster = await admin.GetFromJsonAsync<JsonNode>("/api/admin/cluster");
Check("ключи этого выхода стали общими", cluster?["ready"]?.GetValue<bool>() == true && cluster["awg"]!["port"]!.GetValue<int>() == 41234);
var accounts = await admin.GetFromJsonAsync<JsonArray>("/api/admin/accounts");
var ivanRow = accounts!.FirstOrDefault(a => a!["account"]!["name"]!.GetValue<string>() == "Иван");
Check("Иван и его устройства перенесены в API", ivanRow?["devices"]?.AsArray().Count == 2);
Check("после первой синхронизации подключения на месте", PeerCount() == 3, Conf());

Console.WriteLine("Изменения из API доходят до сервера:");
var mama = await (await admin.PostAsJsonAsync("/api/admin/accounts", new { name = "Мама" })).Content.ReadFromJsonAsync<JsonNode>();
var dev = await (await admin.PostAsJsonAsync($"/api/admin/accounts/{mama!["id"]}/devices", new { name = "Android", kind = "Android" })).Content.ReadFromJsonAsync<JsonNode>();
var devIp = dev!["device"]!["ip"]!.GetValue<string>();
Check("адрес нового устройства не занят служебной учёткой", devIp != "10.8.1.3" && devIp != "10.8.1.1" && devIp != "10.8.1.2", devIp);
await agent.CycleAsync(CancellationToken.None);
Check("новое устройство появилось на сервере", Conf().Contains(devIp + "/32") && PeerCount() == 4, devIp);
var limits = File.ReadAllText(MayakServer.LimitsPath);
Check("лимит нового устройства применён", limits.Contains(devIp + " 35000 35000"), limits);

await admin.PatchAsJsonAsync($"/api/admin/accounts/{mama["id"]}", new { enabled = false });
await agent.CycleAsync(CancellationToken.None);
Check("приостановка человека убирает его подключение", !Conf().Contains(devIp + "/32"));
await admin.PatchAsJsonAsync($"/api/admin/accounts/{mama["id"]}", new { enabled = true });
await agent.CycleAsync(CancellationToken.None);
Check("включение возвращает подключение", Conf().Contains(devIp + "/32"));
await admin.DeleteAsync($"/api/admin/devices/{dev["device"]!["id"]}");
await agent.CycleAsync(CancellationToken.None);
Check("удалённое в API устройство отозвано на сервере", !Conf().Contains(devIp + "/32") && PeerCount() == 3);
Check("служебная учётка проверки не тронута", PeerCount() == 3);

Console.WriteLine("Защита от сбоя API:");
var ivanDevices = ivanRow!["devices"]!.AsArray().Select(d => d!["id"]!.GetValue<Guid>()).ToList();
var extra = new List<Guid>();
for (int i = 0; i < 3; i++)
{
    var d = await (await admin.PostAsJsonAsync($"/api/admin/accounts/{mama["id"]}/devices", new { name = "Планшет " + i, kind = "Android" })).Content.ReadFromJsonAsync<JsonNode>();
    extra.Add(d!["device"]!["id"]!.GetValue<Guid>());
}
await agent.CycleAsync(CancellationToken.None);
int before = PeerCount();
foreach (var id in ivanDevices.Concat(extra)) await admin.DeleteAsync($"/api/admin/devices/{id}");
await agent.CycleAsync(CancellationToken.None);
var servers = await admin.GetFromJsonAsync<JsonArray>("/api/admin/servers");
var err = servers!.First()!["lastError"]?.GetValue<string>();
Check("отзыв всех подключений разом не применён, ошибка видна в админке", PeerCount() == before && err?.Contains("похоже на сбой") == true, err);

Console.WriteLine("Вход (каскад):");
var entry = await (await admin.PostAsJsonAsync("/api/admin/servers", new { name = "Москва", role = "entry", host = "5.42.104.30" })).Content.ReadFromJsonAsync<JsonNode>();
await admin.PatchAsJsonAsync($"/api/admin/servers/{entry!["server"]!["id"]}", new { targetExitId = created["server"]!["id"]!.GetValue<Guid>() });
var entryAgent = AgentFor(entry["agentToken"]!.GetValue<string>());
await entryAgent.CycleAsync(CancellationToken.None);
var relayConf = File.Exists("/etc/mayak-relay.conf") ? File.ReadAllText("/etc/mayak-relay.conf") : "";
Check("вход настроил пересылку на выход", relayConf.Contains("TARGET_HOST=\"45.131.185.211\"") && relayConf.Contains("udp:41234:41234"), relayConf);
await admin.PatchAsJsonAsync($"/api/admin/servers/{entry["server"]!["id"]}", new { clearTarget = true });
await entryAgent.CycleAsync(CancellationToken.None);
Check("снятие цели снимает пересылку", !File.Exists("/etc/mayak-relay.conf"));

await factory.DisposeAsync();
NpgsqlConnection.ClearAllPools();
await using (var conn = new NpgsqlConnection($"{pg};Database=postgres"))
{
    await conn.OpenAsync();
    await new NpgsqlCommand($"DROP DATABASE IF EXISTS {dbName} WITH (FORCE)", conn).ExecuteNonQueryAsync();
}

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
if (failed > 0) Console.WriteLine("Журнал агента:\n  " + string.Join("\n  ", log.TakeLast(30)));
return failed == 0 ? 0 : 1;
