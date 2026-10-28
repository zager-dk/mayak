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
var (gwPriv, gwPub) = Mayak.Core.Gateway.GatewayCrypto.GenerateKeyPair();
var gwKeyPath = Path.Combine(Path.GetTempPath(), $"mayak-gw-{dbName}.pem");
File.WriteAllText(gwKeyPath, gwPriv);
Environment.SetEnvironmentVariable("MAYAK_Gateway__PrivateKeyPath", gwKeyPath);
using var gwRsa = System.Security.Cryptography.RSA.Create();
gwRsa.ImportFromPem(gwPub);

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

    var bot = new TelegramBotService(fakeTg, new TelegramOptions { Token = "test", PublicUrl = "https://mayaklight.ru" }, factory.Services.GetRequiredService<IServiceScopeFactory>(),
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
        var button = fakeTg.Sent.LastOrDefault(m => m.Chat == tgId)?.ButtonUrl;
        Check($"{first}: бот прислал кнопку «Вернуться на сайт» с кодом входа", button == $"https://mayaklight.ru/my/?login={id}", button);
        var viaButton = await http.GetAsync($"/api/auth/telegram/{id}");
        Check($"{first}: вход завершается и по кнопке из бота (другой браузер)", viaButton.StatusCode == HttpStatusCode.OK);
        var again = await http.GetAsync($"/api/auth/telegram/{id}");
        Check($"{first}: больше двух раз код входа не работает", again.StatusCode == HttpStatusCode.Gone);
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

    Console.WriteLine("Кабинет на сайте:");
    var page = await http.GetStringAsync("/my/");
    Check("страница кабинета открывается по /my/", page.Contains("Войти через Telegram"));
    var guest = As(guestToken);
    var mine = await guest.PostAsJsonAsync("/api/devices", new { name = "", kind = "IPhone" });
    var mineBody = await mine.Content.ReadFromJsonAsync<JsonNode>();
    var files = mineBody?["files"];
    Check("человек сам заводит устройство", mine.IsSuccessStatusCode && mineBody!["device"]!["name"]!.GetValue<string>() == "iPhone", mineBody?.ToJsonString());
    Check("сразу получает ключ vpn://, файл .conf и QR-код", files?["vpnKey"]?.GetValue<string>().StartsWith("vpn://") == true &&
          files["conf"]!.GetValue<string>().Contains("[Interface]") && files["qrConf"]!.GetValue<string>().StartsWith("data:image/png;base64,") &&
          files["confName"]!.GetValue<string>().EndsWith(".conf"));
    Check("и запасную ссылку VLESS", files?["vless"]?.GetValue<string>().StartsWith("vless://") == true);
    var myId = mineBody!["device"]!["id"]!.GetValue<string>();
    Check("ключ своего устройства можно открыть снова", (await guest.GetAsync($"/api/devices/{myId}/files")).IsSuccessStatusCode);
    Check("чужое устройство недоступно", (await guest.GetAsync($"/api/devices/{lpDevice.Id}/files")).StatusCode == HttpStatusCode.NotFound);
    await guest.PostAsJsonAsync("/api/devices", new { name = "Ноутбук", kind = "Windows" });
    await guest.PostAsJsonAsync("/api/devices", new { name = "Планшет", kind = "Android" });
    var over = await guest.PostAsJsonAsync("/api/devices", new { name = "Четвёртое", kind = "Android" });
    Check("больше лимита устройств — нельзя", over.StatusCode == HttpStatusCode.Conflict);
    Check("удаление своего устройства", (await guest.DeleteAsync($"/api/devices/{myId}")).StatusCode == HttpStatusCode.NoContent);
    var meWithLoc = await guest.GetFromJsonAsync<JsonNode>("/api/me");
    Check("в кабинете город активного выхода", meWithLoc?["location"]?["city"]?.GetValue<string>() == "Хельсинки");

    async Task<JsonNode> LoginInvite(long tgId, string first, string code)
    {
        var start = await (await http.PostAsJsonAsync("/api/auth/telegram", new { invite = code })).Content.ReadFromJsonAsync<JsonNode>();
        var id = start!["requestId"]!.GetValue<string>();
        await Say(tgId, "/start " + id, first);
        return (await (await http.GetAsync($"/api/auth/telegram/{id}")).Content.ReadFromJsonAsync<JsonNode>())!;
    }
    var mamaId = mamaRow["account"]!["id"]!.GetValue<string>();
    var inv = await (await owner.PostAsync($"/api/admin/accounts/{mamaId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>();
    var invUrl = inv!["url"]!.GetValue<string>();
    Check("приглашение ведёт в кабинет", invUrl.StartsWith("https://mayaklight.ru/my/?invite="));
    var invCode = invUrl.Split("invite=")[1];
    var mamaLogin = await LoginInvite(333, "Мария", invCode);
    Check("по приглашению человек входит в свой заведённый аккаунт", mamaLogin["account"]?["id"]?.GetValue<string>() == mamaId && mamaLogin["account"]!["enabled"]!.GetValue<bool>());
    var mamaMe = await As(mamaLogin["token"]!.GetValue<string>()).GetFromJsonAsync<JsonNode>("/api/me");
    Check("и видит свои устройства", mamaMe?["devices"]?.AsArray().Count > 0);
    var reuse = await http.PostAsJsonAsync("/api/auth/telegram", new { invite = invCode });
    Check("приглашение одноразовое", reuse.StatusCode == HttpStatusCode.Gone);
    var direct = (await (await owner.PostAsync($"/api/admin/accounts/{mamaId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>().Split("invite=")[1];
    var byLink = await http.PostAsJsonAsync("/api/auth/invite", new { invite = direct });
    var byLinkBody = await byLink.Content.ReadFromJsonAsync<JsonNode>();
    Check("по ссылке кабинет открывается сразу, без Telegram", byLink.IsSuccessStatusCode && byLinkBody?["account"]?["id"]?.GetValue<string>() == mamaId);
    var linkMe = await As(byLinkBody!["token"]!.GetValue<string>()).GetFromJsonAsync<JsonNode>("/api/me");
    Check("и в нём устройства человека", linkMe?["devices"]?.AsArray().Count > 0);
    Check("ссылка одноразовая", (await http.PostAsJsonAsync("/api/auth/invite", new { invite = direct })).StatusCode == HttpStatusCode.Gone);
    Check("неизвестная ссылка не пускает", (await http.PostAsJsonAsync("/api/auth/invite", new { invite = "nope" })).StatusCode == HttpStatusCode.Gone);

    var (lateToken, lateAcc) = await Login(444, "Пётр", "petr");
    var petr = await (await owner.PostAsJsonAsync("/api/admin/accounts", new { name = "Пётр (старый)" })).Content.ReadFromJsonAsync<JsonNode>();
    await owner.PostAsJsonAsync($"/api/admin/accounts/{petr!["id"]}/devices", new { name = "Android", kind = "Android" });
    var petrInv = (await (await owner.PostAsync($"/api/admin/accounts/{petr["id"]}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>().Split("invite=")[1];
    var petrLogin = await LoginInvite(444, "Пётр", petrInv);
    Check("если человек успел войти сам, пустой аккаунт заменяется приглашённым", petrLogin["account"]?["id"]?.GetValue<string>() == petr["id"]!.GetValue<string>() &&
          (await As(lateToken).GetAsync("/api/me")).StatusCode == HttpStatusCode.Unauthorized);

    Console.WriteLine("Шлюз для приложения Маяк:");
    async Task<JsonNode> Gw(string method, object payload)
    {
        var (body, session) = Mayak.Core.Gateway.GatewayCrypto.SealRequest(JsonSerializer.Serialize(payload), gwRsa);
        var resp = await http.PostAsync($"/gw/v1/{method}", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        var raw = await resp.Content.ReadAsByteArrayAsync();
        return JsonNode.Parse(Mayak.Core.Gateway.GatewayCrypto.OpenResponse(raw, session))!;
    }
    string NewKey() => Curve25519.GenerateKeyPair().PublicKey;
    var gwInfo = await owner.GetFromJsonAsync<JsonNode>("/api/admin/gateway");
    Check("админка показывает адрес шлюза и открытый ключ для сборки приложения", gwInfo?["ready"]?.GetValue<bool>() == true &&
          gwInfo["endpoint"]!.GetValue<string>() == "https://mayaklight.ru/gw/" && gwInfo["publicKey"]!.GetValue<string>().Contains("BEGIN PUBLIC KEY"));
    var pubPem = await http.GetStringAsync("/gw/public-key");
    Check("открытый ключ шлюза доступен для сборки приложения", pubPem.Trim() == gwPub.Trim());
    var guestKey = (await guest.GetFromJsonAsync<JsonNode>("/api/app-key"))!["key"]!.GetValue<string>();
    var sub = JsonNode.Parse(VpnKeyCodec.Decode(guestKey))!;
    var apiKey = sub["auth_data"]!["api_key"]!.GetValue<string>();
    Check("ключ подписки: формат подписки Amnezia (config_version 2, auth_data)", sub["config_version"]!.GetValue<int>() == 2 &&
          sub["api_config"]!["service_type"]!.GetValue<string>() == "amnezia-premium" && apiKey.Length > 20);
    Check("ключ подписки не меняется при повторном запросе", (await guest.GetFromJsonAsync<JsonNode>("/api/app-key"))!["key"]!.GetValue<string>() == guestKey);
    var devsBefore = (await guest.GetFromJsonAsync<JsonNode>("/api/me"))!["devices"]!.AsArray().Count;
    var pk1 = NewKey();
    var payload = new Dictionary<string, object?>
    {
        ["os_version"] = "ios", ["app_version"] = "4.9.0", ["installation_uuid"] = "inst-1", ["service_type"] = "amnezia-premium",
        ["service_protocol"] = "awg", ["user_country_code"] = "ru", ["public_key"] = pk1, ["auth_data"] = new { api_key = apiKey },
    };
    var cfg1 = await Gw("config", payload);
    var cfgJson = cfg1["config"]?.GetValue<string>() is { } k ? JsonNode.Parse(VpnKeyCodec.Decode(k)) : null;
    Check("v1/config выдаёт настройки в формате шлюза", cfgJson?["config_version"]?.GetValue<int>() == 2 &&
          cfgJson["containers"]![0]!["awg"]!["last_config"]!.GetValue<string>().Contains("$WIREGUARD_CLIENT_PRIVATE_KEY") &&
          cfgJson["auth_data"]!["api_key"]!.GetValue<string>() == apiKey, cfg1.ToJsonString()[..Math.Min(300, cfg1.ToJsonString().Length)]);
    Check("в настройках страна и срок обновления", cfgJson?["api_config"]?["server_country_code"]?.GetValue<string>() == "fi" &&
          cfgJson["api_config"]!["public_key"]!["expires_at"]!.GetValue<string>().Length > 0);
    var appDev = (await guest.GetFromJsonAsync<JsonNode>("/api/me"))!["devices"]!.AsArray().FirstOrDefault(d => d!["kind"]!.GetValue<string>() == "IPhone");
    Check("устройство приложения появилось в кабинете (ключ только в приложении)", appDev != null && appDev["canExport"]!.GetValue<bool>() == false);
    var st = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("и уходит на серверы с ключом приложения", st!.Accounts.SelectMany(a => a.Devices).Any(d => d.PublicKey == pk1));
    var pk2 = NewKey();
    payload["public_key"] = pk2;
    await Gw("config", payload);
    st = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    var all = st!.Accounts.SelectMany(a => a.Devices).ToList();
    Check("повторный запрос той же установки меняет ключ, а не добавляет устройство", all.Any(d => d.PublicKey == pk2) && all.All(d => d.PublicKey != pk1) &&
          (await guest.GetFromJsonAsync<JsonNode>("/api/me"))!["devices"]!.AsArray().Count == devsBefore + 1);
    var info = await Gw("account_info", new { auth_data = new { api_key = apiKey }, installation_uuid = "inst-1" });
    Check("v1/account_info: устройства и лимит", info["max_device_count"]?.GetValue<int>() == 3 &&
          info["issued_configs"]!.AsArray().Any(x => x!["installation_uuid"]!.GetValue<string>() == "inst-1"));
    payload["installation_uuid"] = "inst-2"; payload["public_key"] = NewKey();
    var overLimit = await Gw("config", payload);
    Check("сверх лимита — 409, приложение покажет «лимит устройств»", overLimit["http_status"]?.GetValue<int>() == 409);
    var bad = await Gw("config", new Dictionary<string, object?>(payload) { ["auth_data"] = new { api_key = "wrong" } });
    Check("чужой ключ подписки — 404 Account not found.", bad["http_status"]?.GetValue<int>() == 404 && bad["message"]!.GetValue<string>() == "Account not found.");
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { enabled = false });
    payload["installation_uuid"] = "inst-1";
    var paused = await Gw("config", payload);
    Check("приостановленному — 402", paused["http_status"]?.GetValue<int>() == 402);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { enabled = true });
    var revoked = await Gw("revoke_config", new { auth_data = new { api_key = apiKey }, installation_uuid = "inst-1" });
    Check("v1/revoke_config отключает устройство", revoked["ok"]?.GetValue<bool>() == true &&
          (await guest.GetFromJsonAsync<JsonNode>("/api/me"))!["devices"]!.AsArray().All(d => d!["kind"]!.GetValue<string>() != "IPhone"));

    Console.WriteLine("Длинный опрос агента:");
    var cur = (await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!.Revision;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var waiting = agent.GetFromJsonAsync<AgentState>($"{AgentPaths.State}?since={cur}&wait=20", json);
    await Task.Delay(500);
    await guest.PostAsJsonAsync("/api/devices", new { name = "Срочно", kind = "Android" });
    var woke = await waiting;
    Check("агент узнаёт об изменении сразу, а не через полминуты", woke!.Revision > cur && sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
    sw.Restart();
    var idle = await agent.GetFromJsonAsync<AgentState>($"{AgentPaths.State}?since={woke.Revision}&wait=1", json);
    Check("без изменений ответ приходит по истечении ожидания", idle!.Revision == woke.Revision && sw.Elapsed >= TimeSpan.FromMilliseconds(900));

    Console.WriteLine("Своё устройство и выход:");
    var myDevices = await owner.GetFromJsonAsync<JsonNode>("/api/me");
    Check("у владельца пока нет устройств", myDevices!["devices"]!.AsArray().Count == 0);
    var logout = await owner.PostAsync("/api/logout", null);
    Check("после выхода токен не работает", logout.StatusCode == HttpStatusCode.NoContent && (await owner.GetAsync("/api/me")).StatusCode == HttpStatusCode.Unauthorized);
}
finally
{
    File.Delete(gwKeyPath);
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
    public sealed record Message(long Chat, string Text, string? ButtonUrl = null);
    public List<Message> Sent { get; } = new();
    public FakeTelegram() : base(new TelegramOptions { Token = "test" }) { Username = "mayak_test_bot"; }
    public override Task SendAsync(long chatId, string text, string buttonText, string buttonUrl, CancellationToken ct)
    {
        lock (Sent) Sent.Add(new Message(chatId, text, buttonUrl));
        return Task.CompletedTask;
    }
    public override Task SendAsync(long chatId, string text, CancellationToken ct)
    {
        lock (Sent) Sent.Add(new Message(chatId, text));
        return Task.CompletedTask;
    }
}
