using Microsoft.AspNetCore.Hosting;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Telegram;
using Mayak.Core.Agent;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;
using Mayak.Core.Export;
using Mayak.Core.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

// Тест API Маяка на настоящем PostgreSQL. Запуск:
// dotnet run --project tests/Mayak.ApiTest -- "Host=127.0.0.1;Port=55432;Username=postgres"
int failed = 0, passed = 0;
void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

var server = args.ElementAtOrDefault(0) ?? "Host=127.0.0.1;Port=55432;Username=postgres";
var dbName = "mayak_test_" + Guid.NewGuid().ToString("N")[..8];
var cs = $"{server};Database={dbName}";
Environment.SetEnvironmentVariable("MAYAK_ConnectionStrings__Db", cs);
Environment.SetEnvironmentVariable("MAYAK_Telegram__Polling", "false");
Environment.SetEnvironmentVariable("MAYAK_PublicUrl", "https://mayaklight.ru");

var fakeTg = new FakeTelegram();
await using var factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b =>
    b.UseContentRoot(AppContext.BaseDirectory).ConfigureTestServices(s =>
    {
        s.AddSingleton(new TelegramOptions { Token = "test" });
        s.AddSingleton<TelegramClient>(fakeTg);
    }));
var http = factory.CreateClient();
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

try
{
    Console.WriteLine("Запуск:");
    var health = await http.GetFromJsonAsync<JsonNode>("/health");
    Check("API отвечает, база создана миграциями", health?["ok"]?.GetValue<bool>() == true);

    var bot = new TelegramBotService(fakeTg, new TelegramOptions { Token = "test" }, factory.Services.GetRequiredService<IServiceScopeFactory>(),
        factory.Services.GetRequiredService<Microsoft.Extensions.Logging.ILogger<TelegramBotService>>());
    Task Say(long userId, string text, string first = "Тест", string? username = null) =>
        bot.HandleAsync(JsonNode.Parse(JsonSerializer.Serialize(new
        {
            text,
            chat = new { id = userId },
            from = new { id = userId, is_bot = false, first_name = first, username },
        }))!, CancellationToken.None);

    async Task<(string Token, JsonNode Account)> Login(long tgId, string first, string username)
    {
        var start = await (await http.PostAsync("/api/auth/telegram", null)).Content.ReadFromJsonAsync<JsonNode>();
        var id = start!["requestId"]!.GetValue<string>();
        var pending = await http.GetAsync($"/api/auth/telegram/{id}");
        Check($"{first}: до подтверждения в боте — «ждём»", pending.StatusCode == HttpStatusCode.Accepted);
        Check($"{first}: ссылка ведёт в бота с кодом запроса", start["botUrl"]!.GetValue<string>() == $"https://t.me/mayak_test_bot?start={id}");
        await Say(tgId, "/start " + id, first, username);
        var done = await http.GetAsync($"/api/auth/telegram/{id}?client=test");
        var body = await done.Content.ReadFromJsonAsync<JsonNode>();
        var again = await http.GetAsync($"/api/auth/telegram/{id}");
        Check($"{first}: ссылку входа нельзя использовать повторно", again.StatusCode == HttpStatusCode.Gone);
        return (body!["token"]!.GetValue<string>(), body["account"]!);
    }
    HttpClient As(string token)
    {
        var c = factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    Console.WriteLine("Вход через Telegram:");
    var (ownerToken, ownerAcc) = await Login(111, "Давид", "david");
    Check("первый вошедший — владелец, доступ сразу включён", ownerAcc["role"]!.GetValue<string>() == "owner" && ownerAcc["enabled"]!.GetValue<bool>());
    Check("бот подтвердил вход владельцу", fakeTg.Sent.Any(m => m.Chat == 111 && m.Text.Contains("владельцем")));
    var owner = As(ownerToken);
    var me = await owner.GetFromJsonAsync<JsonNode>("/api/me");
    Check("/api/me по токену сеанса", me?["account"]?["name"]?.GetValue<string>() == "Давид");

    var (guestToken, guestAcc) = await Login(222, "Гость", "guest");
    Check("следующий человек ждёт одобрения", !guestAcc["enabled"]!.GetValue<bool>() && guestAcc["role"]!.GetValue<string>() == "user");
    var notify = fakeTg.Sent.LastOrDefault(m => m.Chat == 111 && m.Text.Contains("/approve"));
    Check("владельцу пришла заявка с командой одобрения", notify != null);
    var approve = notify!.Text.Split('\n').Last(l => l.Contains("/approve")).Split(':', 2)[1].Trim();
    await Say(111, approve, "Давид", "david");
    var guestMe = await As(guestToken).GetFromJsonAsync<JsonNode>("/api/me");
    Check("после /approve доступ гостя включён", guestMe?["account"]?["enabled"]?.GetValue<bool>() == true);
    Check("гостю пришло уведомление", fakeTg.Sent.Any(m => m.Chat == 222 && m.Text.Contains("одобрен")));
    await Say(222, "/approve 12345678", "Гость", "guest");
    Check("обычный человек не может одобрять", fakeTg.Sent.Last().Chat == 222 && !fakeTg.Sent.Last().Text.Contains("включён"));

    Console.WriteLine("Права:");
    Check("без токена — 401", (await factory.CreateClient().GetAsync("/api/me")).StatusCode == HttpStatusCode.Unauthorized);
    Check("пользователю админка закрыта — 403", (await As(guestToken).GetAsync("/api/admin/servers")).StatusCode == HttpStatusCode.Forbidden);

    Console.WriteLine("Серверы и агент:");
    var created = await (await owner.PostAsJsonAsync("/api/admin/servers", new { name = "Финляндия, Хельсинки", role = "exit", host = "45.131.185.211", city = "Хельсинки", country = "Финляндия", countryCode = "fi" })).Content.ReadFromJsonAsync<JsonNode>();
    var agentToken = created!["agentToken"]!.GetValue<string>();
    Check("сервер добавлен, выдана команда установки агента", created["install"]!.GetValue<string>().Contains("--api https://mayaklight.ru --token " + agentToken));
    Check("первый выход сразу активный", created["server"]!["active"]!.GetValue<bool>());
    var agent = As(agentToken);
    Check("чужой токен агента — 401", (await As("wrong").GetAsync(AgentPaths.State)).StatusCode == HttpStatusCode.Unauthorized);

    var awg = new ServerEndpoint { Port = 41234, ServerPublicKey = Curve25519.GenerateKeyPair().PublicKey, PresharedKey = Curve25519.GeneratePresharedKey(), Parameters = AwgParameters.GenerateV2() };
    var legacy = new MayakDatabase();
    var mama = new VpnUser { Name = "Мама" };
    var (lp, lpub) = Curve25519.GenerateKeyPair();
    mama.Devices.Add(new VpnDevice { Name = "iPhone", Kind = DeviceKind.IPhone, PrivateKey = lp, PublicKey = lpub, Ip = "10.8.1.2", XrayId = Guid.NewGuid().ToString(), DownMbps = 35, UpMbps = 35 });
    mama.Devices.Add(new VpnDevice { Name = "Ноутбук", Kind = DeviceKind.Windows, PrivateKey = "", PublicKey = Curve25519.GenerateKeyPair().PublicKey, Ip = "10.8.1.3", DownMbps = 50, UpMbps = 0 });
    legacy.Users.Add(mama);
    var hello = await (await agent.PostAsJsonAsync(AgentPaths.Hello, new AgentHello
    {
        Version = "test",
        Identity = new AgentIdentity { Awg = awg, AwgServerPrivateKey = "server-private", Xray = new XrayEndpoint { Port = 443, PublicKey = "realitypub", ShortId = "abcd" }, XrayPrivateKey = "realitypriv" },
        Legacy = legacy,
    }, json)).Content.ReadFromJsonAsync<AgentHelloReply>(json);
    Check("ключи выхода приняты, пользователи Маяка перенесены", hello?.ImportedDevices == 2, $"{hello?.ImportedDevices}");

    await agent.PostAsJsonAsync(AgentPaths.Report, new AgentReport { ReservedIps = { "10.8.1.4" } }, json);
    var fam = await (await owner.PostAsJsonAsync("/api/admin/accounts", new { name = "Бабушка" })).Content.ReadFromJsonAsync<JsonNode>();
    var devResp = await owner.PostAsJsonAsync($"/api/admin/accounts/{fam!["id"]}/devices", new { name = "Android", kind = "Android" });
    var dev = await devResp.Content.ReadFromJsonAsync<JsonNode>();
    Check("администратор выдаёт устройство своему человеку", devResp.IsSuccessStatusCode, dev?.ToJsonString());
    var newIp = dev?["device"]?["ip"]?.GetValue<string>();
    Check("новый адрес не пересекается с перенесёнными и занятыми на сервере", newIp == "10.8.1.5", newIp);
    var key = dev!["vpnKey"]!.GetValue<string>();
    var parsed = JsonNode.Parse(VpnKeyCodec.Decode(key));
    Check("файл .vpn: адрес активного выхода и оба протокола", parsed?["hostName"]?.GetValue<string>() == "45.131.185.211" && parsed.ToJsonString().Contains("amnezia-xray"), parsed?["hostName"]?.ToString());
    Check("файл .conf с ключом устройства", dev["conf"]!.GetValue<string>().Contains("Endpoint = 45.131.185.211:41234"));

    var state = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    var stateDevices = state!.Accounts.SelectMany(a => a.Devices).ToList();
    Check("состояние для агента: все устройства", stateDevices.Count == 3, $"{stateDevices.Count}");
    Check("лимиты: свой у ноутбука, тариф у остальных", stateDevices.Single(d => d.Name == "Ноутбук").DownMbps == 50 && stateDevices.Single(d => d.Name == "Android").DownMbps == 35);
    long rev1 = state.Revision;

    var lpDevice = stateDevices.Single(d => d.Name == "iPhone");
    await agent.PostAsJsonAsync(AgentPaths.Report, new AgentReport { Peers = { new AgentPeerStats { PublicKey = lpDevice.PublicKey, LatestHandshake = DateTime.UtcNow, RxBytes = 1000, TxBytes = 2000 } } }, json);
    var accounts = await owner.GetFromJsonAsync<JsonArray>("/api/admin/accounts");
    var mamaRow = accounts!.First(a => a!["account"]!["name"]!.GetValue<string>() == "Мама");
    Check("статистика из отчёта агента видна в админке", mamaRow!["devices"]!.AsArray().Any(d => d!["rxBytes"]!.GetValue<long>() == 1000));
    var oldFiles = await owner.GetFromJsonAsync<JsonNode>($"/api/admin/devices/{lpDevice.Id}/files");
    Check("перенесённому устройству можно выдать файл заново", oldFiles?["vpnKey"]?.GetValue<string>().StartsWith("vpn://") == true);
    var noKey = await owner.GetAsync($"/api/admin/devices/{stateDevices.Single(d => d.Name == "Ноутбук").Id}/files");
    Check("устройству без сохранённого ключа файл не выдаётся", noKey.StatusCode == HttpStatusCode.BadRequest);

    await owner.PatchAsJsonAsync($"/api/admin/accounts/{mamaRow["account"]!["id"]}", new { enabled = false });
    var state2 = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("приостановка человека: ревизия выросла, аккаунт выключен", state2!.Revision > rev1 && !state2.Accounts.Single(a => a.Name == "Мама").Enabled);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{mamaRow["account"]!["id"]}", new { enabled = true, paidUntil = DateTime.UtcNow.AddDays(-1) });
    var state3 = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("истёкшая подписка выключает доступ", !state3!.Accounts.Single(a => a.Name == "Мама").Enabled);

    Console.WriteLine("Вход (каскад):");
    var entry = await (await owner.PostAsJsonAsync("/api/admin/servers", new { name = "Москва", role = "entry", host = "5.42.104.30" })).Content.ReadFromJsonAsync<JsonNode>();
    var entryAgent = As(entry!["agentToken"]!.GetValue<string>());
    var entryState = await entryAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("вход без цели ничего не пересылает", entryState!.Relay == null && entryState.Accounts.Count == 0);
    await owner.PatchAsJsonAsync($"/api/admin/servers/{entry["server"]!["id"]}", new { targetExitId = created["server"]!["id"]!.GetValue<Guid>() });
    entryState = await entryAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("вход пересылает на выход: порты AmneziaWG и Xray", entryState!.Relay?.TargetHost == "45.131.185.211" && entryState.Relay.AwgPort == 41234 && entryState.Relay.XrayPort == 443);
    var filesViaEntry = await owner.GetFromJsonAsync<JsonNode>($"/api/admin/devices/{lpDevice.Id}/files");
    Check("в файлах теперь адрес входа", JsonNode.Parse(VpnKeyCodec.Decode(filesViaEntry!["vpnKey"]!.GetValue<string>()))?["hostName"]?.GetValue<string>() == "5.42.104.30");

    Console.WriteLine("Своё устройство и выход:");
    var myDevices = await owner.GetFromJsonAsync<JsonNode>("/api/me");
    Check("у владельца пока нет устройств", myDevices!["devices"]!.AsArray().Count == 0);
    var logout = await owner.PostAsync("/api/logout", null);
    Check("после выхода токен не работает", logout.StatusCode == HttpStatusCode.NoContent && (await owner.GetAsync("/api/me")).StatusCode == HttpStatusCode.Unauthorized);
}
finally
{
    await factory.DisposeAsync();
    NpgsqlConnection.ClearAllPools();
    await using var conn = new NpgsqlConnection($"{server};Database=postgres");
    await conn.OpenAsync();
    await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS {dbName} WITH (FORCE)", conn);
    await cmd.ExecuteNonQueryAsync();
}

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
return failed == 0 ? 0 : 1;

sealed class FakeTelegram : TelegramClient
{
    public sealed record Message(long Chat, string Text);
    public List<Message> Sent { get; } = new();
    public FakeTelegram() : base(new TelegramOptions { Token = "test" }) { Username = "mayak_test_bot"; }
    public override Task SendAsync(long chatId, string text, CancellationToken ct)
    {
        lock (Sent) Sent.Add(new Message(chatId, text));
        return Task.CompletedTask;
    }
}
