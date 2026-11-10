// Ключ на устройство: вход по почте и паролю → токен установки → шлюз; лимит, переустановка, автоосвобождение,
// замена, старый ключ аккаунта, привязка Telegram. Аргумент — строка подключения к PostgreSQL без Database.
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Core.Export;
using Mayak.Core.Gateway;
using Mayak.Core.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

if (args.Length != 1) throw new ArgumentException("Pass a PostgreSQL server connection string without Database.");
var adminCs = new NpgsqlConnectionStringBuilder(args[0]) { Database = "postgres" }.ConnectionString;
var dbName = "mayak_devaccess_" + Guid.NewGuid().ToString("N")[..10];
await using (var admin = new NpgsqlConnection(adminCs))
{
    await admin.OpenAsync();
    await using var create = new NpgsqlCommand($"CREATE DATABASE \"{dbName}\"", admin);
    await create.ExecuteNonQueryAsync();
}
var appCs = new NpgsqlConnectionStringBuilder(args[0]) { Database = dbName }.ConnectionString;
Environment.SetEnvironmentVariable("MAYAK_ConnectionStrings__Db", appCs);
Environment.SetEnvironmentVariable("MAYAK_Telegram__Polling", "false");
Environment.SetEnvironmentVariable("MAYAK_Probes__Enabled", "false");
Environment.SetEnvironmentVariable("MAYAK_PublicUrl", "https://mayak.test");
Environment.SetEnvironmentVariable("MAYAK_Devices__KeyRequestsPerMinute", "60");
var (gwPriv, gwPub) = GatewayCrypto.GenerateKeyPair();
var gwKeyPath = Path.Combine(Path.GetTempPath(), $"mayak-gw-{dbName}.pem");
File.WriteAllText(gwKeyPath, gwPriv);
Environment.SetEnvironmentVariable("MAYAK_Gateway__PrivateKeyPath", gwKeyPath);
using var gwRsa = RSA.Create();
gwRsa.ImportFromPem(gwPub);

var fakeTg = new FakeTelegram();
await using var factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b =>
{
    b.UseContentRoot(AppContext.BaseDirectory);
    b.ConfigureLogging(l => l.ClearProviders());
    b.ConfigureTestServices(s =>
    {
        s.AddSingleton(new TelegramOptions { Token = "test" });
        s.AddSingleton<TelegramClient>(fakeTg);
    });
});
var http = factory.CreateClient();
var failed = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}"); if (!ok) failed++; }

async Task<T> Db<T>(Func<MayakDb, Task<T>> f)
{
    await using var scope = factory.Services.CreateAsyncScope();
    return await f(scope.ServiceProvider.GetRequiredService<MayakDb>());
}
async Task<(HttpStatusCode Status, JsonNode? Body)> Send(HttpMethod method, string path, object? payload = null, string? bearer = null)
{
    using var req = new HttpRequestMessage(method, path);
    if (payload != null) req.Content = JsonContent.Create(payload);
    if (bearer != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
    using var resp = await http.SendAsync(req);
    var text = await resp.Content.ReadAsStringAsync();
    return (resp.StatusCode, string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text));
}
async Task<JsonObject> Gateway(string method, JsonObject payload)
{
    var (body, session) = GatewayCrypto.SealRequest(payload.ToJsonString(), gwRsa);
    using var resp = await http.PostAsync("/gw/v1/" + method, new StringContent(body, Encoding.UTF8, "application/json"));
    return JsonNode.Parse(GatewayCrypto.OpenResponse(await resp.Content.ReadAsByteArrayAsync(), session))!.AsObject();
}
JsonObject ConfigReq(string apiKey, string install, string? pub = null) => new()
{
    ["auth_data"] = new JsonObject { ["api_key"] = apiKey },
    ["installation_uuid"] = install,
    ["public_key"] = pub ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    ["os_version"] = "android 14",
    ["app_version"] = "5.1.0.18",
};
string KeyOf(JsonNode? body) => JsonNode.Parse(VpnKeyCodec.Decode(body!["key"]!.GetValue<string>()))!["auth_data"]!["api_key"]!.GetValue<string>();
string ApiKeyInConfig(JsonObject r) => JsonNode.Parse(VpnKeyCodec.Decode(r["config"]!.GetValue<string>()))!["auth_data"]!["api_key"]!.GetValue<string>();
static string H(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
async Task<bool> SentContains(long chat, string fragment)
{
    for (int i = 0; i < 40; i++)
    {
        lock (fakeTg.Sent) if (fakeTg.Sent.Any(m => m.Chat == chat && m.Text.Contains(fragment))) return true;
        await Task.Delay(50);
    }
    return false;
}

try
{
    using var _ = factory.CreateClient(); // миграции
    var accountId = Guid.NewGuid();
    var invite = Tokens.New();
    const long adminTg = 900001, userTg = 900002;
    await Db(async db =>
    {
        db.Cluster.Add(new ClusterIdentity { Id = 1, Revision = 1, PublicHost = "vpn.mayak.test", AwgJson = JsonSerializer.Serialize(new ServerEndpoint
        {
            Host = "192.0.2.10", Port = 51820, ServerPublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            PresharedKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        }) });
        db.Accounts.Add(new Account { Name = "owner", Role = Roles.Owner, TelegramId = adminTg });
        db.Accounts.Add(new Account { Id = accountId, Name = "Родственник", MaxDevices = 2 });
        db.Invites.Add(new Invite { CodeHash = Tokens.Hash(invite), AccountId = accountId, ExpiresAt = DateTime.UtcNow.AddDays(1) });
        await db.SaveChangesAsync();
        return 0;
    });

    var reg = await Send(HttpMethod.Post, "/api/auth/register", new { invite, email = "relative@mayak.test", password = "long enough password 1" });
    var session = reg.Body?["token"]?.GetValue<string>();
    Check("регистрация по приглашению с почтой и паролем выдаёт сеанс", reg.Status == HttpStatusCode.OK && session != null);

    var bad = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "", deviceHash = H("a") }, session);
    Check("без installationId — 400", bad.Status == HttpStatusCode.BadRequest);
    var badHash = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0001", deviceHash = "xyz" }, session);
    Check("неверный deviceHash — 400", badHash.Status == HttpStatusCode.BadRequest);
    var noSession = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0001" });
    Check("без сеанса — 401", noSession.Status == HttpStatusCode.Unauthorized);

    // Устройство A
    var a1 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0001", deviceHash = H("phone-A"), os = "android 14", appVersion = "5.1.0.18" }, session);
    var tokenA1 = a1.Status == HttpStatusCode.OK ? KeyOf(a1.Body) : "";
    Check($"ключ устройства A выдан (status={(int)a1.Status})", a1.Status == HttpStatusCode.OK && tokenA1.StartsWith("md1."));
    var deviceA = a1.Body?["deviceId"]?.GetValue<Guid>() ?? Guid.Empty;
    var storedHash = await Db(db => db.Devices.Where(d => d.Id == deviceA).Select(d => d.AppTokenHash).FirstAsync());
    Check("в базе только хеш токена", storedHash == Tokens.Hash(tokenA1) && storedHash != tokenA1);
    Check("уведомление о новом устройстве администратору", await SentContains(adminTg, "Новое устройство в аккаунте «Родственник»"));

    var cfgA = await Gateway("config", ConfigReq(tokenA1, "install-aaaa-0001"));
    Check($"шлюз выдаёт настройки по токену устройства (http_status={cfgA["http_status"]})", cfgA["config"] != null);
    Check("настройки возвращают тот же токен, а не ключ аккаунта", cfgA["config"] != null && ApiKeyInConfig(cfgA) == tokenA1);
    var foreignInstall = await Gateway("config", ConfigReq(tokenA1, "install-other-9999"));
    Check("токен с чужой установки — 403", foreignInstall["http_status"]?.GetValue<int>() == 403);
    var countAfterForeign = await Db(db => db.Devices.CountAsync(d => d.AccountId == accountId));
    Check("по токену новое устройство не создаётся", countAfterForeign == 1);

    var a2 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0001", deviceHash = H("phone-A") }, session);
    var tokenA2 = KeyOf(a2.Body);
    Check("повторный запрос той же установки — то же устройство, новый токен", a2.Body?["deviceId"]?.GetValue<Guid>() == deviceA && tokenA2 != tokenA1);
    var oldToken = await Gateway("config", ConfigReq(tokenA1, "install-aaaa-0001"));
    Check("старый токен перестал работать", oldToken["http_status"]?.GetValue<int>() == 404);

    // Переустановка: новый installation_uuid, тот же постоянный ID.
    var re = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0002", deviceHash = H("phone-A") }, session);
    var tokenA3 = KeyOf(re.Body);
    var countAfterReinstall = await Db(db => db.Devices.CountAsync(d => d.AccountId == accountId));
    Check("переустановка не занимает новое место", re.Body?["deviceId"]?.GetValue<Guid>() == deviceA && countAfterReinstall == 1);
    var cfgRe = await Gateway("config", ConfigReq(tokenA3, "install-aaaa-0002"));
    Check("после переустановки шлюз работает с новой установкой", cfgRe["config"] != null);

    // Устройство B заполняет лимит (2).
    var b = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-bbbb-0001", deviceHash = H("pc-B"), os = "windows 11" }, session);
    var deviceB = b.Body?["deviceId"]?.GetValue<Guid>() ?? Guid.Empty;
    var tokenB = KeyOf(b.Body);
    Check("устройство B выдано", b.Status == HttpStatusCode.OK && b.Body?["deviceName"]?.GetValue<string>() == "Компьютер");
    var c = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-cccc-0001", deviceHash = H("tab-C"), os = "android 13" }, session);
    Check("третье устройство при лимите 2 — 409 DEVICE_LIMIT со списком",
        c.Status == HttpStatusCode.Conflict && c.Body?["code"]?.GetValue<string>() == "DEVICE_LIMIT" && c.Body?["devices"]?.AsArray().Count == 2);

    // Автоосвобождение: B не появлялся 40 дней.
    await Db(db => db.Devices.Where(d => d.Id == deviceB).ExecuteUpdateAsync(u => u
        .SetProperty(d => d.CreatedAt, DateTime.UtcNow.AddDays(-40)).SetProperty(d => d.ConfigFetchedAt, (DateTime?)null).SetProperty(d => d.LastHandshake, (DateTime?)null)));
    var c2 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-cccc-0001", deviceHash = H("tab-C"), os = "android 13" }, session);
    var deviceC = c2.Body?["deviceId"]?.GetValue<Guid>() ?? Guid.Empty;
    var bGone = await Db(db => db.Devices.AnyAsync(d => d.Id == deviceB));
    Check("неактивное 40 дней устройство освобождает место", c2.Status == HttpStatusCode.OK && !bGone);
    Check("в уведомлении — освобождённое устройство", await SentContains(adminTg, "Освобождено неактивных: Компьютер"));
    var bAfter = await Gateway("config", ConfigReq(tokenB, "install-bbbb-0001"));
    Check("токен освобождённого устройства не работает", bAfter["http_status"]?.GetValue<int>() == 404);

    // Замена по выбору.
    var unknown = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-dddd-0001", replaceDeviceId = Guid.NewGuid() }, session);
    Check("замена несуществующего устройства — 404", unknown.Status == HttpStatusCode.NotFound);
    var d = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-dddd-0001", replaceDeviceId = deviceC, os = "windows 10" }, session);
    var cGone = await Db(db => db.Devices.AnyAsync(x => x.Id == deviceC));
    var countAfterReplace = await Db(db => db.Devices.CountAsync(x => x.AccountId == accountId));
    Check("замена выбранного устройства при полном лимите", d.Status == HttpStatusCode.OK && !cGone && countAfterReplace == 2);
    var tokenD = KeyOf(d.Body);
    var installD = "install-dddd-0001";

    // Старый ключ аккаунта.
    var legacy = await Send(HttpMethod.Get, "/api/app-key", null, session);
    var legacyKey = KeyOf(legacy.Body);
    Check("старый ключ аккаунта по-прежнему выдаётся", legacy.Status == HttpStatusCode.OK && !legacyKey.StartsWith("md1."));
    var legacyOnToken = await Gateway("config", ConfigReq(legacyKey, "install-aaaa-0002"));
    Check("ключ аккаунта не представляет установку со своим токеном", legacyOnToken["http_status"]?.GetValue<int>() == 403);
    var legacyNew = await Gateway("config", ConfigReq(legacyKey, "install-eeee-0001"));
    Check("ключ аккаунта упирается в тот же лимит", legacyNew["http_status"]?.GetValue<int>() == 409);
    var legacyRevoke = await Gateway("revoke_config", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = legacyKey }, ["installation_uuid"] = installD });
    Check("ключом аккаунта нельзя отключить устройство со своим токеном", legacyRevoke["http_status"]?.GetValue<int>() == 403);

    var info = await Gateway("account_info", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = tokenA3 } });
    Check("список устройств по токену", info["issued_configs"]?.AsArray().Count == 2 && info["max_device_count"]?.GetValue<int>() == 2);

    // Сброс ключа аккаунта не трогает устройства с токенами.
    var reset = await Send(HttpMethod.Post, "/api/app-key/reset", null, session);
    var countAfterReset = await Db(db => db.Devices.CountAsync(x => x.AccountId == accountId));
    Check("сброс ключа аккаунта оставляет устройства с токенами", reset.Status == HttpStatusCode.NoContent && countAfterReset == 2);
    var aStill = await Gateway("config", ConfigReq(tokenA3, "install-aaaa-0002"));
    Check("токен устройства работает после сброса ключа аккаунта", aStill["config"] != null);

    // Отключение с устройства с токеном.
    var revoke = await Gateway("revoke_config", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = tokenA3 }, ["installation_uuid"] = installD });
    var dGone = !await Db(db => db.Devices.AnyAsync(x => x.InstallationId == installD));
    Check("с подтверждённого устройства можно отключить другое", revoke["ok"]?.GetValue<bool>() == true && dGone);
    var dAfter = await Gateway("config", ConfigReq(tokenD, installD));
    Check("отключённое устройство больше не получает настройки", dAfter["http_status"]?.GetValue<int>() == 404);

    // Отключённое администратором устройство.
    await Db(db => db.Devices.Where(x => x.Id == deviceA).ExecuteUpdateAsync(u => u.SetProperty(x => x.Enabled, false)));
    var disabled = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-aaaa-0002", deviceHash = H("phone-A") }, session);
    Check("отключённое устройство не получает новый ключ", disabled.Status == HttpStatusCode.Forbidden);
    await Db(db => db.Devices.Where(x => x.Id == deviceA).ExecuteUpdateAsync(u => u.SetProperty(x => x.Enabled, true)));

    // Привязка Telegram к аккаунту с почтой и паролем.
    var link = await Send(HttpMethod.Post, "/api/auth/telegram/link", null, session);
    var linkId = link.Body?["requestId"]?.GetValue<string>() ?? "";
    Check("запрос привязки Telegram создан", link.Status == HttpStatusCode.OK && link.Body?["botUrl"]?.GetValue<string>()?.EndsWith("?start=" + linkId) == true);
    var pending = await Send(HttpMethod.Get, $"/api/auth/telegram/{linkId}");
    Check("до подтверждения в боте — ждём", pending.Status == HttpStatusCode.Accepted);
    var bot = new TelegramBotService(fakeTg, new TelegramOptions { Token = "test", PublicUrl = "https://mayak.test" },
        factory.Services.GetRequiredService<IServiceScopeFactory>(), factory.Services.GetRequiredService<ILogger<TelegramBotService>>());
    await bot.HandleAsync(JsonNode.Parse(JsonSerializer.Serialize(new
    {
        text = "/start " + linkId,
        chat = new { id = userTg },
        from = new { id = userTg, is_bot = false, first_name = "Родственник", username = "relative_tg" },
    }))!, CancellationToken.None);
    var notYet = await Db(db => db.Accounts.Where(x => x.Id == accountId).Select(x => x.TelegramId).FirstAsync());
    Check("нажатие в боте само по себе не привязывает Telegram", notYet == null);
    var confirmState = await Send(HttpMethod.Get, $"/api/auth/telegram/{linkId}");
    Check("опрос показывает, какой Telegram ждёт подтверждения",
        confirmState.Body?["status"]?.GetValue<string>() == "confirm" && confirmState.Body?["telegram"]?.GetValue<string>() == "relative_tg" && confirmState.Body?["token"] == null);
    await bot.HandleAsync(JsonNode.Parse(JsonSerializer.Serialize(new
    {
        text = "/start " + linkId,
        chat = new { id = 900003L },
        from = new { id = 900003L, is_bot = false, first_name = "Посторонний", username = "stranger" },
    }))!, CancellationToken.None);
    var afterStranger = await Send(HttpMethod.Get, $"/api/auth/telegram/{linkId}");
    Check("второе нажатие по той же ссылке не перехватывает привязку", afterStranger.Body?["telegram"]?.GetValue<string>() == "relative_tg");
    var foreignInvite = Tokens.New();
    var foreignId = Guid.NewGuid();
    await Db(async db =>
    {
        db.Accounts.Add(new Account { Id = foreignId, Name = "Чужой", MaxDevices = 1 });
        db.Invites.Add(new Invite { CodeHash = Tokens.Hash(foreignInvite), AccountId = foreignId, ExpiresAt = DateTime.UtcNow.AddDays(1) });
        await db.SaveChangesAsync();
        return 0;
    });
    var foreignReg = await Send(HttpMethod.Post, "/api/auth/register", new { invite = foreignInvite, email = "foreign@mayak.test", password = "another long password" });
    var foreignSession = foreignReg.Body?["token"]?.GetValue<string>();
    var foreignConfirm = await Send(HttpMethod.Post, $"/api/auth/telegram/link/{linkId}/confirm", null, foreignSession);
    Check("чужой сеанс не может подтвердить привязку", foreignConfirm.Status == HttpStatusCode.Gone);
    Check("опрос отдаёт ID ожидающего Telegram", confirmState.Body?["telegramId"]?.GetValue<string>() == userTg.ToString());
    var wrongId = await Send(HttpMethod.Post, $"/api/auth/telegram/link/{linkId}/confirm", new { telegramId = "900003" }, session);
    Check("подтверждение с другим ID Telegram отклоняется", wrongId.Status == HttpStatusCode.Gone);
    var confirm = await Send(HttpMethod.Post, $"/api/auth/telegram/link/{linkId}/confirm", new { telegramId = userTg.ToString() }, session);
    Check("подтверждение в приложении привязывает Telegram", confirm.Status == HttpStatusCode.OK && confirm.Body?["telegramLinked"]?.GetValue<bool>() == true);
    var linked = await Db(db => db.Accounts.Where(x => x.Id == accountId).Select(x => x.TelegramId).FirstAsync());
    var accountsCount = await Db(db => db.Accounts.CountAsync());
    Check("Telegram привязан к этому же аккаунту, новый не создан", linked == userTg && accountsCount == 3);
    var polled = await Send(HttpMethod.Get, $"/api/auth/telegram/{linkId}");
    Check("опрос привязки не выдаёт сеанс", polled.Status == HttpStatusCode.OK && polled.Body?["status"]?.GetValue<string>() == "linked" && polled.Body?["token"] == null);
    var confirmAgain = await Send(HttpMethod.Post, $"/api/auth/telegram/link/{linkId}/confirm", null, session);
    Check("повторное подтверждение — 410", confirmAgain.Status == HttpStatusCode.Gone);
    var again = await Send(HttpMethod.Post, "/api/auth/telegram/link", null, session);
    Check("повторная привязка — 409", again.Status == HttpStatusCode.Conflict);
    var me = await Send(HttpMethod.Get, "/api/me", null, session);
    Check("кабинет показывает привязанный Telegram", me.Body?["account"]?["telegram"]?.GetValue<string>() == "relative_tg"
                                                   && me.Body?["account"]?["telegramLinked"]?.GetValue<bool>() == true);

    var e = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-ffff-0001", deviceHash = H("phone-F"), os = "android 15" }, session);
    Check("новое устройство после привязки", e.Status == HttpStatusCode.OK);
    Check("уведомление приходит и владельцу аккаунта в Telegram", await SentContains(userTg, "Новое устройство"));
    var newDevice = e.Body?["deviceId"]?.GetValue<Guid>() ?? Guid.Empty;
    var newInfo = await Db(async db => await db.Devices.Where(x => x.Id == newDevice)
        .Select(x => new { x.AutoConnectManaged, x.StableDeviceHash }).FirstAsync());
    var autoManaged = newInfo.AutoConnectManaged;
    var storedStable = newInfo.StableDeviceHash;
    Check("В2: устройство из device-key сразу считается автоподключаемым (не «старым» для мест на выходах)", autoManaged);
    Check("хеш постоянного ID хранится в пределах аккаунта, а не как прислан", storedStable != null && storedStable != H("phone-F"));
    Check("ответ для нового устройства — reused=false", e.Body?["reused"]?.GetValue<bool>() == false);

    // ---- Б1: смена ключа при включённом VPN не ломает OFF/ON ----
    var exitId = Guid.NewGuid();
    var legacyAccountId = Guid.NewGuid();
    const string legacyPassword = "legacy account password";
    await Db(async db =>
    {
        db.Servers.Add(new Server { Id = exitId, Name = "exit", Host = "192.0.2.10", Role = ServerRoles.Exit, AgentTokenHash = Tokens.Hash("synthetic-agent"),
            Active = true, AutoSelectEnabled = true, ExpectedEgressIpsJson = "[\"81.29.149.103\"]" });
        db.Accounts.Add(new Account { Id = legacyAccountId, Name = "Старый клиент", MaxDevices = 3, AppKey = "synthetic-legacy-account-key",
            LoginEmailNormalized = PasswordCredentials.NormalizeEmail("legacy@mayak.test"), PasswordHash = PasswordCredentials.Hash(legacyPassword) });
        await db.SaveChangesAsync();
        return 0;
    });
    async Task Ack() => await Db(async db =>
    {
        var cl = await db.Cluster.SingleAsync(); var s = await db.Servers.SingleAsync(x => x.Id == exitId); var now = DateTime.UtcNow;
        s.ProvisioningStatus = "installed"; s.ProvisionIdentityMatched = true; s.ProvisioningIdentityHash = Mayak.Api.Provisioning.ProvisioningPlanner.IdentityHash(cl);
        s.ProvisioningConfirmedRevision = cl.Revision; s.ProvisioningConfirmedAt = now; s.LastSeen = now;
        s.LastReport = JsonSerializer.Serialize(new Mayak.Core.Agent.AgentReport { AppliedRevision = cl.Revision, ProvisioningProof = new Mayak.Core.Agent.ProvisioningRuntimeProof
            { AwgRunning = true, XrayRunning = true, ConfigurationLoaded = true, PostApplyCheckPassed = true } });
        await db.SaveChangesAsync();
        return 0;
    });
    const string legacyInstall = "install-legacy-0001";
    var legacyPub = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    JsonObject Adm(string key, string action, string attempt, Guid? allocation = null)
    {
        var o = new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = key }, ["installation_uuid"] = legacyInstall, ["public_key"] = legacyPub,
            ["action"] = action, ["attempt_id"] = attempt, ["candidate_id"] = exitId.ToString() };
        if (allocation != null) o["allocation_id"] = allocation.ToString();
        return o;
    }
    var legacyCfg = ConfigReq("synthetic-legacy-account-key", legacyInstall, legacyPub);
    legacyCfg["mayak_auto_connect"] = 1;
    await Gateway("config", legacyCfg);
    await Ack();
    var acq1 = await Gateway("admission", Adm("synthetic-legacy-account-key", "acquire", "attempt_legacy_000001"));
    var alloc1 = Guid.TryParse(acq1["allocation_id"]?.GetValue<string>(), out var a1g) ? a1g : Guid.Empty;
    Check($"старый клиент занял место ключом аккаунта ({acq1["code"]})", alloc1 != Guid.Empty);

    var legacyLogin = await Send(HttpMethod.Post, "/api/auth/login", new { email = "legacy@mayak.test", password = legacyPassword });
    var legacySession = legacyLogin.Body?["token"]?.GetValue<string>();
    Check($"вход старого аккаунта по почте и паролю (status={(int)legacyLogin.Status})", legacySession != null);
    var t1Resp = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = legacyInstall }, legacySession);
    Check($"ключ устройства для установки старого клиента (status={(int)t1Resp.Status}, {t1Resp.Body?["error"]})", t1Resp.Status == HttpStatusCode.OK);
    if (t1Resp.Status != HttpStatusCode.OK) throw new InvalidOperationException("stop");
    var t1 = KeyOf(t1Resp.Body);
    Check("вход на той же установке — reused=true", t1Resp.Body?["reused"]?.GetValue<bool>() == true);
    var released1 = await Db(db => db.AwgAllocations.Where(x => x.Id == alloc1).Select(x => x.ReleasedAt).FirstAsync());
    Check("смена ключа освобождает место устройства", released1 != null);
    var oldRelease = await Gateway("admission", Adm("synthetic-legacy-account-key", "release", "attempt_legacy_000001", alloc1));
    Check($"OFF со старым ключом аккаунта после смены ключа проходит ({oldRelease["code"]})", oldRelease["released"] != null);
    var oldReconcile = await Gateway("admission", Adm("synthetic-legacy-account-key", "reconcile", "attempt_legacy_000001"));
    Check($"reconcile со старым ключом аккаунта проходит ({oldReconcile["code"]})", oldReconcile["reconciled"]?.GetValue<bool>() == true);
    var oldAcquire = await Gateway("admission", Adm("synthetic-legacy-account-key", "acquire", "attempt_legacy_000009"));
    Check("новое место старым ключом аккаунта не выдаётся", oldAcquire["code"]?.GetValue<string>() == "REVOKED");
    var acq2 = await Gateway("admission", Adm(t1, "acquire", "attempt_token_0000001"));
    var alloc2 = Guid.TryParse(acq2["allocation_id"]?.GetValue<string>(), out var a2g) ? a2g : Guid.Empty;
    Check($"ON с новым токеном после смены ключа работает ({acq2["code"]})", alloc2 != Guid.Empty);

    var t2 = KeyOf((await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = legacyInstall }, legacySession)).Body);
    var staleRelease = await Gateway("admission", Adm(t1, "release", "attempt_token_0000001", alloc2));
    Check($"md1→md1: OFF с предыдущим токеном проходит ({staleRelease["code"]})", staleRelease["released"] != null);
    var staleAcquire = await Gateway("admission", Adm(t1, "acquire", "attempt_token_0000002"));
    Check("предыдущим токеном нельзя занять новое место", staleAcquire["code"]?.GetValue<string>() == "REVOKED");
    var staleConfig = await Gateway("config", ConfigReq(t1, legacyInstall, legacyPub));
    var staleInfo = await Gateway("account_info", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = t1 } });
    Check("предыдущий токен не получает настройки и список устройств", staleConfig["http_status"]?.GetValue<int>() == 404 && staleInfo["http_status"]?.GetValue<int>() == 404);
    await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = legacyInstall }, legacySession); // t3: t1 уже два поколения назад
    var veryStale = await Gateway("admission", Adm(t1, "reconcile", "attempt_token_0000001"));
    Check($"ключом, которым открыта попытка, её можно закрыть и через две смены ключа ({veryStale["code"]})", veryStale["reconciled"]?.GetValue<bool>() == true);
    var acq3 = await Gateway("admission", Adm(t2, "acquire", "attempt_token_0000003"));
    Check("ключ двух поколений назад не работает для подключения", acq3["code"]?.GetValue<string>() == "REVOKED");

    // ---- Остаток В1: A → B → A на одной установке — сервер возвращает то же устройство A ----
    var abaInstall = "install-aba-000001";
    var abaA1 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = abaInstall }, foreignSession);
    var abaB = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = abaInstall }, legacySession);
    var abaA2 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = abaInstall }, foreignSession);
    Check("A→B→A: в B своё новое устройство, в A — прежнее (reused и тот же deviceId)",
        abaB.Status == HttpStatusCode.Conflict || abaB.Body?["reused"]?.GetValue<bool>() == false);
    Check("A→B→A: возврат в A узнаёт прежнее устройство",
        abaA2.Body?["reused"]?.GetValue<bool>() == true && abaA2.Body?["deviceId"]?.GetValue<Guid>() == abaA1.Body?["deviceId"]?.GetValue<Guid>());

    // ---- З-1: место, открытое до миграции (AuthKeyHash = NULL), закрывается ключом аккаунта и после двух смен ключа ----
    var preId = Guid.NewGuid();
    var legacyDeviceId = await Db(db => db.Devices.Where(x => x.InstallationId == legacyInstall).Select(x => x.Id).FirstAsync());
    await Db(async db =>
    {
        db.AwgAllocations.Add(new AwgAllocation { Id = preId, DeviceId = legacyDeviceId, ServerId = exitId, AttemptId = "attempt_premigration_1", AuthKeyHash = null,
            ReleasedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
        return 0;
    });
    var preReconcile = await Gateway("admission", Adm("synthetic-legacy-account-key", "reconcile", "attempt_premigration_1"));
    Check($"старое место без хеша ключа закрывается ключом аккаунта ({preReconcile["code"]})", preReconcile["reconciled"]?.GetValue<bool>() == true);

    // ---- В3: отключённое устройство по своему токену не читает список и не отключает другие ----
    var dis1 = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-dis-0001" }, legacySession);
    var disToken = KeyOf(dis1.Body);
    var disId = dis1.Body?["deviceId"]?.GetValue<Guid>() ?? Guid.Empty;
    await Db(db => db.Devices.Where(x => x.Id == disId).ExecuteUpdateAsync(u => u.SetProperty(x => x.Enabled, false)));
    var disInfo = await Gateway("account_info", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = disToken } });
    var disRevoke = await Gateway("revoke_config", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = disToken }, ["installation_uuid"] = legacyInstall });
    var legacyStill = await Db(db => db.Devices.AnyAsync(x => x.InstallationId == legacyInstall));
    Check("отключённое устройство не читает список устройств", disInfo["http_status"]?.GetValue<int>() == 402);
    Check("отключённое устройство не отключает другие", disRevoke["http_status"]?.GetValue<int>() == 402 && legacyStill);

    // ---- Замечание 4: отключённые администратором устройства не освобождаются и не заменяются ----
    await Db(db => db.Devices.Where(x => x.Id == disId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedAt, DateTime.UtcNow.AddDays(-60))
        .SetProperty(x => x.ConfigFetchedAt, (DateTime?)null).SetProperty(x => x.LastHandshake, (DateTime?)null)));
    await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-third-0001" }, legacySession); // 3 из 3
    var fourth = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-fourth-001" }, legacySession);
    var disStill = await Db(db => db.Devices.AnyAsync(x => x.Id == disId));
    Check("отключённое неактивное устройство не освобождается само", fourth.Status == HttpStatusCode.Conflict && disStill);
    var replaceDisabled = await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-fourth-001", replaceDeviceId = disId }, legacySession);
    Check("отключённое устройство нельзя заменить", replaceDisabled.Status == HttpStatusCode.Forbidden && await Db(db => db.Devices.AnyAsync(x => x.Id == disId)));

    // ---- В4: отключение и замена одного устройства одновременно — без голого HTTP 500 ----
    var raceOk = true;
    for (int round = 0; round < 4; round++)
    {
        var victimInstall = $"install-race-{round:D4}";
        var thirdId = await Db(db => db.Devices.Where(x => x.AccountId == legacyAccountId && x.Enabled && x.InstallationId != legacyInstall)
            .OrderBy(x => x.CreatedAt).Select(x => x.Id).FirstAsync());
        var thirdInstall = await Db(db => db.Devices.Where(x => x.Id == thirdId).Select(x => x.InstallationId!).FirstAsync());
        var currentT = KeyOf((await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = legacyInstall }, legacySession)).Body);
        var replaceTask = Send(HttpMethod.Post, "/api/app/device-key", new { installationId = victimInstall, replaceDeviceId = thirdId }, legacySession);
        var revokeTask = Gateway("revoke_config", new JsonObject { ["auth_data"] = new JsonObject { ["api_key"] = currentT }, ["installation_uuid"] = thirdInstall });
        try { await Task.WhenAll(replaceTask, revokeTask); }
        catch (Exception ex) { raceOk = false; Console.WriteLine("race: " + ex.GetType().Name); }
    }
    Check("гонка замены и отключения отвечает ошибкой шлюза, а не HTTP 500", raceOk);

    // ---- Замечание 8: ограничение частоты device-key ----
    var limited = false;
    for (int i = 0; i < 65 && !limited; i++)
        limited = (await Send(HttpMethod.Post, "/api/app/device-key", new { installationId = "install-foreign-01" }, foreignSession)).Status == HttpStatusCode.TooManyRequests;
    Check("частые запросы ключа устройства ограничиваются (429)", limited);
}
finally
{
    await factory.DisposeAsync();
    NpgsqlConnection.ClearAllPools();
    await using var admin = new NpgsqlConnection(adminCs);
    await admin.OpenAsync();
    await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{dbName}\" WITH (FORCE)", admin);
    await drop.ExecuteNonQueryAsync();
    File.Delete(gwKeyPath);
}
Console.WriteLine(failed == 0 ? "ALL PASS" : $"FAILED: {failed}");
return failed == 0 ? 0 : 1;

sealed class FakeTelegram : TelegramClient
{
    public sealed record Message(long Chat, string Text);
    public List<Message> Sent { get; } = new();
    public FakeTelegram() : base(new TelegramOptions { Token = "test" }) { Username = "mayak_test_bot"; }
    public override Task SendAsync(long chatId, string text, string buttonText, string buttonUrl, CancellationToken ct)
    {
        lock (Sent) Sent.Add(new Message(chatId, text));
        return Task.CompletedTask;
    }
    public override Task SendAsync(long chatId, string text, CancellationToken ct)
    {
        lock (Sent) Sent.Add(new Message(chatId, text));
        return Task.CompletedTask;
    }
}
