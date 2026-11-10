using Mayak.Api.Data;
using Mayak.Api.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;

if (args.Length != 1) throw new ArgumentException("Pass a PostgreSQL server connection string without Database.");
var adminCs = new NpgsqlConnectionStringBuilder(args[0]) { Database = "postgres" }.ConnectionString;
var dbName = "mayak_emailauth_" + Guid.NewGuid().ToString("N")[..10];
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
Environment.SetEnvironmentVariable("MAYAK_Gateway__PrivateKeyPath", Path.Combine(Path.GetTempPath(), "mayak-auth-gateway-not-present.pem"));
await using var factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b => { b.UseContentRoot(AppContext.BaseDirectory); b.ConfigureLogging(logging => logging.ClearProviders()); });
var client = factory.CreateClient();
var failed = 0;
void Check(string name, bool condition) { Console.WriteLine($"{(condition ? "PASS" : "FAIL")} {name}"); if (!condition) failed++; }
async Task<(Guid id, string raw)> Seed(string name, bool enabled = true, DateTime? paidUntil = null)
{
    var id = Guid.NewGuid(); var raw = Tokens.New();
    await using var scope = factory.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
    db.Accounts.Add(new Account { Id = id, Name = name, Enabled = enabled, PaidUntil = paidUntil });
    db.Invites.Add(new Invite { CodeHash = Tokens.Hash(raw), AccountId = id, ExpiresAt = DateTime.UtcNow.AddDays(1) });
    await db.SaveChangesAsync(); return (id, raw);
}
async Task<(HttpStatusCode status, JsonNode? body, bool noStore)> Post(string path, object payload, string? bearer = null)
{
    using var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(payload) };
    if (bearer != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
    using var response = await client.SendAsync(req);
    var text = await response.Content.ReadAsStringAsync();
    return (response.StatusCode, string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text), response.Headers.CacheControl?.NoStore == true);
}

try
{
    using var _ = factory.CreateClient(); // starts app and applies all migrations
    var (accountId, invite) = await Seed("auth-basic");
    var password = "correct horse battery staple";
    var registered = await Post("/api/auth/register", new { invite, email = "  Test.User@Example.org ", password });
    var token = registered.body?["token"]?.GetValue<string>();
    var registeredHasPassword = registered.body?["account"]?["hasPassword"]?.GetValue<bool>();
    Check($"invite register succeeds and returns account/token (status={(int)registered.status}, token={token != null}, hasPassword={registeredHasPassword})", registered.status == HttpStatusCode.OK && token != null && registeredHasPassword == true);
    Check("registration has no-store", registered.noStore);
    var login = await Post("/api/auth/login", new { email = "test.user@example.org", password });
    Check("case-normalized login succeeds", login.status == HttpStatusCode.OK);
    var wrong = await Post("/api/auth/login", new { email = "missing@example.org", password = "incorrect password value" });
    Check("unknown email is generic 401", wrong.status == HttpStatusCode.Unauthorized && wrong.body?["error"]?.GetValue<string>() == "Неверный адрес или пароль.");
    var wrongPassword = await Post("/api/auth/login", new { email = "test.user@example.org", password = "incorrect password value" });
    Check("wrong password uses same generic 401", wrongPassword.status == wrong.status && wrongPassword.body?["error"]?.GetValue<string>() == wrong.body?["error"]?.GetValue<string>());
    var me = await client.GetAsync("/api/me"); me.Dispose();
    using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/me"))
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(req);
        Check("registered session works with existing /api/me", response.StatusCode == HttpStatusCode.OK);
    }
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var acc = await db.Accounts.SingleAsync(a => a.Id == accountId);
        Check("password stored only as PBKDF2 and login identity normalized", acc.PasswordHash != password && acc.PasswordHash!.StartsWith("pbkdf2-sha256$v1$600000$") && acc.LoginEmailNormalized == "TEST.USER@EXAMPLE.ORG");
        var used = await db.Invites.SingleAsync(i => i.AccountId == accountId);
        Check("successful registration consumes invite", used.UsedAt != null);
    }
    var legacyId = Guid.NewGuid(); var legacyToken = Tokens.New(); var existingDeviceId = Guid.NewGuid();
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.Accounts.Add(new Account { Id = legacyId, Name = "legacy-account" });
        db.Devices.Add(new Device { Id = existingDeviceId, AccountId = legacyId, Name = "existing-device", AwgPublicKey = "legacy-auth-pub", Ip = "10.222.0.2", XrayId = "legacy-auth-xray" });
        db.Sessions.Add(new Session { TokenHash = Tokens.Hash(legacyToken), AccountId = legacyId, Client = "legacy" });
        await db.SaveChangesAsync();
    }
    var bound = await Post("/api/auth/credentials", new { email = "Legacy.User@example.org", password }, legacyToken);
    Check("unbound authenticated account can create credentials", bound.status == HttpStatusCode.OK && bound.body?["account"]?["hasPassword"]?.GetValue<bool>() == true);
    using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/me"))
    {
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", legacyToken);
        using var response = await client.SendAsync(req);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync());
        Check("credential setup retains existing session and device", response.StatusCode == HttpStatusCode.OK && body?["devices"]?.AsArray().Any(d => d?["id"]?.GetValue<string>() == existingDeviceId.ToString()) == true);
    }

    var (usedId, usedInvite) = await Seed("auth-used");
    await using (var scope = factory.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<MayakDb>(); var inv = await db.Invites.SingleAsync(i => i.AccountId == usedId); inv.UsedAt = DateTime.UtcNow; await db.SaveChangesAsync(); }
    Check("used invite rejected", (await Post("/api/auth/register", new { invite = usedInvite, email = "used@example.org", password })).status == HttpStatusCode.Gone);
    Check("invalid invite rejected", (await Post("/api/auth/register", new { invite = "not-a-valid-invitation", email = "invalid-invite@example.org", password })).status == HttpStatusCode.Gone);
    var (expiredId, expiredInvite) = await Seed("auth-expired");
    await using (var scope = factory.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<MayakDb>(); var inv = await db.Invites.SingleAsync(i => i.AccountId == expiredId); inv.ExpiresAt = DateTime.UtcNow.AddMinutes(-1); await db.SaveChangesAsync(); }
    Check("expired invite rejected", (await Post("/api/auth/register", new { invite = expiredInvite, email = "expired@example.org", password })).status == HttpStatusCode.Gone);
    var (disabledId, disabledInvite) = await Seed("auth-disabled", enabled: false);
    Check("disabled account rejected", (await Post("/api/auth/register", new { invite = disabledInvite, email = "disabled@example.org", password })).status == HttpStatusCode.Forbidden);
    var (expiredAccountId, expiredAccountInvite) = await Seed("auth-account-expired", paidUntil: DateTime.UtcNow.AddDays(-1));
    Check("expired account rejected", (await Post("/api/auth/register", new { invite = expiredAccountInvite, email = "account-expired@example.org", password })).status == HttpStatusCode.Forbidden);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        await db.Accounts.Where(a => a.Id == disabledId).ExecuteUpdateAsync(s => s.SetProperty(a => a.LoginEmailNormalized, "DISABLED@EXAMPLE.ORG").SetProperty(a => a.PasswordHash, PasswordCredentials.Hash(password)));
        await db.Accounts.Where(a => a.Id == expiredAccountId).ExecuteUpdateAsync(s => s.SetProperty(a => a.LoginEmailNormalized, "EXPIRED@EXAMPLE.ORG").SetProperty(a => a.PasswordHash, PasswordCredentials.Hash(password)));
    }
    Check("disabled account cannot log in", (await Post("/api/auth/login", new { email = "disabled@example.org", password })).status == HttpStatusCode.Forbidden);
    Check("expired account cannot log in", (await Post("/api/auth/login", new { email = "expired@example.org", password })).status == HttpStatusCode.Forbidden);
    var (duplicateId, duplicateInvite) = await Seed("auth-duplicate");
    Check("duplicate normalized email rejected", (await Post("/api/auth/register", new { invite = duplicateInvite, email = "TEST.USER@example.org", password })).status == HttpStatusCode.Conflict);
    await using (var scope = factory.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<MayakDb>(); Check("duplicate collision does not consume invite", (await db.Invites.SingleAsync(i => i.AccountId == duplicateId)).UsedAt == null); }
    var (raceId, raceInvite) = await Seed("auth-race");
    var race = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => Post("/api/auth/register", new { invite = raceInvite, email = "race@example.org", password })));
    Check("concurrent repeated invite redeems exactly once", race.Count(r => r.status == HttpStatusCode.OK) == 1);
    var (sameAccountId, inviteA) = await Seed("auth-same-account");
    string inviteB = Tokens.New();
    await using (var scope = factory.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<MayakDb>(); db.Invites.Add(new Invite { CodeHash = Tokens.Hash(inviteB), AccountId = sameAccountId, ExpiresAt = DateTime.UtcNow.AddDays(1) }); await db.SaveChangesAsync(); }
    var both = await Task.WhenAll(Post("/api/auth/register", new { invite = inviteA, email = "same-account@example.org", password }), Post("/api/auth/register", new { invite = inviteB, email = "other-account@example.org", password }));
    Check("different invites cannot overwrite same account credentials", both.Count(r => r.status == HttpStatusCode.OK) == 1);
    var (collisionAId, collisionA) = await Seed("auth-collision-a");
    var (collisionBId, collisionB) = await Seed("auth-collision-b");
    var sameEmail = await Task.WhenAll(Post("/api/auth/register", new { invite = collisionA, email = "simultaneous@example.org", password }), Post("/api/auth/register", new { invite = collisionB, email = " SIMULTANEOUS@example.org ", password }));
    Check("concurrent duplicate email yields one success and one conflict", sameEmail.Count(r => r.status == HttpStatusCode.OK) == 1 && sameEmail.Count(r => r.status == HttpStatusCode.Conflict) == 1);
    await using (var scope = factory.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<MayakDb>(); var loserId = sameEmail[0].status == HttpStatusCode.OK ? collisionBId : collisionAId; Check("concurrent email collision rolls back losing invite", (await db.Invites.SingleAsync(i => i.AccountId == loserId)).UsedAt == null); }
    var setExisting = await Post("/api/auth/credentials", new { email = "replacement@example.org", password }, token);
    Check("existing credentials cannot be replaced", setExisting.status == HttpStatusCode.Conflict);
    Check("credential setup requires an account session", (await Post("/api/auth/credentials", new { email = "no-session@example.org", password })).status == HttpStatusCode.Unauthorized);
    Check("invalid email and short password validation", (await Post("/api/auth/register", new { invite = "x", email = "bad", password = "short" })).status == HttpStatusCode.BadRequest);
    Check("malformed and unsupported hashes fail closed", !PasswordCredentials.Verify(password, "other$v9$999999999$bad$bad") && !PasswordCredentials.Verify(password, "pbkdf2-sha256$v1$600000$!$!"));

    await using (var rateFactory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b => { b.UseContentRoot(AppContext.BaseDirectory); b.ConfigureLogging(l => l.ClearProviders()); }))
    {
        using var rateClient = rateFactory.CreateClient();
        HttpResponseMessage? last = null;
        for (var i = 0; i < 31; i++)
        {
            last?.Dispose();
            last = await rateClient.PostAsJsonAsync(i % 2 == 0 ? "/api/auth/login" : "/api/auth/register", new { invite = "x", email = "bad", password = "short" });
            if (i < 30) Check("auth request below limit " + i, last.StatusCode != HttpStatusCode.TooManyRequests);
        }
        Check("31st auth request throttled", last!.StatusCode == HttpStatusCode.TooManyRequests);
        Check("429 auth response no-store", last!.Headers.CacheControl?.NoStore == true);
        last.Dispose();
    }

    var (raceStatusId, _) = await Seed("login-status-race");
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        await db.Accounts.Where(a => a.Id == raceStatusId).ExecuteUpdateAsync(s => s.SetProperty(a => a.LoginEmailNormalized, "RACE.STATUS@EXAMPLE.ORG").SetProperty(a => a.PasswordHash, PasswordCredentials.Hash(password)));
    }
    var statusInterceptor = new DisableDuringLogin(appCs, raceStatusId);
    await using (var raceFactory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b =>
    {
        b.UseContentRoot(AppContext.BaseDirectory);
        b.ConfigureLogging(l => l.ClearProviders());
        b.ConfigureServices(s =>
        {
            foreach (var descriptor in s.Where(x => x.ServiceType == typeof(DbContextOptions<MayakDb>)).ToArray()) s.Remove(descriptor);
            s.AddDbContext<MayakDb>(o => o.UseNpgsql(appCs).AddInterceptors(statusInterceptor));
        });
    }))
    {
        using var raceClient = raceFactory.CreateClient();
        using var response = await raceClient.PostAsJsonAsync("/api/auth/login", new { email = "race.status@example.org", password });
        var responseBody = JsonNode.Parse(await response.Content.ReadAsStringAsync());
        Check("status race interception fired", statusInterceptor.Fired);
        Check("account disabled before issuance receives no token", response.StatusCode == HttpStatusCode.Forbidden && responseBody?["token"] == null);
    }
    Console.WriteLine($"RESULT failed={failed}");
}
finally
{
    client.Dispose();
    await using var admin = new NpgsqlConnection(adminCs);
    await admin.OpenAsync();
    await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{dbName}\" WITH (FORCE)", admin);
    await drop.ExecuteNonQueryAsync();
}
return failed == 0 ? 0 : 1;

sealed class DisableDuringLogin(string connectionString, Guid accountId) : DbCommandInterceptor
{
    public bool Fired { get; private set; }

    public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData data, DbDataReader result, CancellationToken cancellationToken = default)
    {
        if (!Fired && command.CommandText.Contains("WHERE a.\"LoginEmailNormalized\"") && command.Parameters.Cast<DbParameter>().Any(p => p.Value?.ToString() == "RACE.STATUS@EXAMPLE.ORG"))
        {
            Fired = true;
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var update = new NpgsqlCommand("UPDATE \"Accounts\" SET \"Enabled\"=false WHERE \"Id\"=@id", connection);
            update.Parameters.AddWithValue("id", accountId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        return result;
    }
}
