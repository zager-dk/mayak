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

var stateDir = "/root/.mayak_agent_state_" + dbName;
AgentRunner AgentFor(string token, bool dryRun = false)
{
    var http = factory.CreateClient();
    return new AgentRunner(new AgentConfig { Api = "http://localhost", Token = token, PublicHost = "45.131.185.211", DryRun = dryRun, StateDir = stateDir }, http, () => new LocalShell("/root/.mayak_agent_tmp"), Log);
}
string Conf() => File.ReadAllText(MayakServer.ConfPath);
int PeerCount() => Conf().Split('\n').Count(l => l.Trim() == "[Peer]");

Console.WriteLine("Пробный запуск агента (человек в API заведён раньше, чем агент вышел на связь):");
var confBefore = Conf();
var created = await (await admin.PostAsJsonAsync("/api/admin/servers", new { name = "Хельсинки", role = "exit", host = "45.131.185.211" })).Content.ReadFromJsonAsync<JsonNode>();
Check("админка выдаёт и пробную команду установки", created!["installDryRun"]?.GetValue<string>().EndsWith("--dry-run") == true);
var mama = await (await admin.PostAsJsonAsync("/api/admin/accounts", new { name = "Мама" })).Content.ReadFromJsonAsync<JsonNode>();
var dry = AgentFor(created["agentToken"]!.GetValue<string>(), dryRun: true);
await dry.CycleAsync(CancellationToken.None);
Check("агент на связи как выход", dry.Role == "exit", string.Join(" | ", log));
var cluster = await admin.GetFromJsonAsync<JsonNode>("/api/admin/cluster");
Check("ключи этого выхода стали общими", cluster?["ready"]?.GetValue<bool>() == true && cluster["awg"]!["port"]!.GetValue<int>() == 41234);
var accounts = await admin.GetFromJsonAsync<JsonArray>("/api/admin/accounts");
var ivanRow = accounts!.FirstOrDefault(a => a!["account"]!["name"]!.GetValue<string>() == "Иван");
Check("Иван и его устройства перенесены в API, хотя там уже были люди", ivanRow?["devices"]?.AsArray().Count == 2);
var dev = await (await admin.PostAsJsonAsync($"/api/admin/accounts/{mama!["id"]}/devices", new { name = "Android", kind = "Android" })).Content.ReadFromJsonAsync<JsonNode>();
var devIp = dev!["device"]!["ip"]!.GetValue<string>();
Check("адрес нового устройства не занят ни Иваном, ни служебной учёткой", devIp != "10.8.1.3" && devIp != "10.8.1.1" && devIp != "10.8.1.2", devIp);
await dry.CycleAsync(CancellationToken.None);
Check("в пробном режиме файлы сервера не изменились", Conf() == confBefore);
var srv = (await admin.GetFromJsonAsync<JsonArray>("/api/admin/servers"))!.First(x => x!["role"]!.GetValue<string>() == "exit")!;
var warn = string.Join(" ", srv["report"]?["warnings"]?.AsArray().Select(w => w!.GetValue<string>()) ?? Array.Empty<string>());
Check("отчёт в админке: пробный режим, добавил бы 1, отозвал бы 0", srv["report"]?["dryRun"]?.GetValue<bool>() == true && warn.Contains("добавил бы 1 и отозвал бы 0"), warn);
Check("резервной копии в пробном режиме нет", !Directory.Exists(Path.Combine(stateDir, "backup")));

Console.WriteLine("Включение по-настоящему:");
var agent = AgentFor(created["agentToken"]!.GetValue<string>());
await agent.CycleAsync(CancellationToken.None);
var backups = Directory.Exists(Path.Combine(stateDir, "backup")) ? Directory.GetDirectories(Path.Combine(stateDir, "backup")) : Array.Empty<string>();
Check("перед первым изменением сделана копия настроек", backups.Length == 1 && File.Exists(Path.Combine(backups[0], "awg", "awg0.conf")) && File.ReadAllText(Path.Combine(backups[0], "awg", "awg0.conf")) == confBefore, string.Join(",", backups));
Check("подключения Ивана на месте", PeerCount() == 4 && ivanRow!["devices"]!.AsArray().All(d => Conf().Contains(d!["ip"]!.GetValue<string>() + "/32")), Conf());
Check("устройство из API появилось на сервере", Conf().Contains(devIp + "/32"), devIp);
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

Console.WriteLine("Устройство, добавленное на сервер мимо API (Маяк для Windows):");
using (var shell = new LocalShell("/root/.mayak_agent_tmp"))
{
    var win = new MayakServer(shell, "127.0.0.1");
    win.Connect();
    var snap = win.Load();
    var petr = new VpnUser { Name = "Пётр" };
    snap.Db.Users.Add(petr);
    win.Save(snap);
    win.AddDevice(snap, petr, "Mac", DeviceKind.Mac, 35, 35);
}
int withPetr = PeerCount();
await admin.PatchAsJsonAsync($"/api/admin/accounts/{mama["id"]}", new { note = "ревизия" });
await agent.CycleAsync(CancellationToken.None);
accounts = await admin.GetFromJsonAsync<JsonArray>("/api/admin/accounts");
var petrRow = accounts!.FirstOrDefault(a => a!["account"]!["name"]!.GetValue<string>() == "Пётр");
Check("агент перенёс его в API, а не отозвал", petrRow?["devices"]?.AsArray().Count == 1 && PeerCount() == withPetr, Conf());
await admin.DeleteAsync($"/api/admin/devices/{petrRow!["devices"]![0]!["id"]}");
await agent.CycleAsync(CancellationToken.None);
Check("удалённое в API — отозвано", PeerCount() == withPetr - 1);
var restarted = AgentFor(created["agentToken"]!.GetValue<string>());
await restarted.CycleAsync(CancellationToken.None);
accounts = await admin.GetFromJsonAsync<JsonArray>("/api/admin/accounts");
petrRow = accounts!.FirstOrDefault(a => a!["account"]!["name"]!.GetValue<string>() == "Пётр");
Check("после перезапуска агента удалённое не возвращается", (petrRow?["devices"]?.AsArray().Count ?? 0) == 0 && PeerCount() == withPetr - 1);

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

try { Directory.Delete(stateDir, true); } catch (IOException) { }

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
if (failed > 0) Console.WriteLine("Журнал агента:\n  " + string.Join("\n  ", log.TakeLast(30)));
return failed == 0 ? 0 : 1;
