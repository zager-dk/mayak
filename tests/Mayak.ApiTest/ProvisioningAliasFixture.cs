using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Api.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Npgsql;

static class ProvisioningAliasFixture
{
    public static async Task RunAsync(string server, Action<string, bool, string?> check)
    {
        var adminSettings = new NpgsqlConnectionStringBuilder(server) { Database = "postgres" };
        if (adminSettings.Host != "127.0.0.1" || adminSettings.Port != 55432)
            throw new InvalidOperationException("Alias fixture requires disposable local PostgreSQL at 127.0.0.1:55432");
        var name = "mayak_provision_alias_" + Guid.NewGuid().ToString("N");
        var settings = new NpgsqlConnectionStringBuilder(server) { Database = name };
        await using (var connection = new NpgsqlConnection(adminSettings.ConnectionString))
        {
            await connection.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE {name}", connection);
            await create.ExecuteNonQueryAsync();
        }
        var environment = new Dictionary<string, string?>
        {
            ["MAYAK_ConnectionStrings__Db"] = settings.ConnectionString,
            ["MAYAK_Telegram__Polling"] = "false",
            ["MAYAK_PublicUrl"] = "https://alias-fixture.example.test",
            ["MAYAK_Gateway__PrivateKeyPath"] = Path.Combine(Path.GetTempPath(), "no-key-" + name),
        };
        var previous = environment.Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
        WebApplicationFactory<MayakDb>? factory = null;
        try
        {
            foreach (var (key, value) in environment) Environment.SetEnvironmentVariable(key, value);
            factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(builder =>
            {
                builder.UseContentRoot(AppContext.BaseDirectory);
                builder.ConfigureLogging(logging => logging.ClearProviders());
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<IProvisioningBackend>();
                    services.AddSingleton<IProvisioningBackend>(new FakeProvisioningBackend());
                });
            });
            using var client = factory.CreateClient();
            var token = Tokens.New();
            var owner = new Account { Name = "alias fixture owner", Role = Roles.Owner, Enabled = true };
            var currentExit = new Server { Name = "existing exit", Role = "exit", Host = "9.9.9.9", Active = true, AgentTokenHash = Tokens.Hash(Tokens.New()) };
            var entry = new Server { Name = "existing entry", Role = "entry", Host = "1.0.0.1", TargetExitId = currentExit.Id, AgentTokenHash = Tokens.Hash(Tokens.New()) };
            var quarantine = new Server { Name = "quarantined target", Role = "exit", Host = "8.8.4.4", ProvisioningStatus = "failed", AgentTokenHash = Tokens.Hash(Tokens.New()) };
            // Reproduce an already persisted unrestricted alias from the old API.
            var oldAlias = new Server { Name = "old mapped duplicate", Role = "exit", Host = "::ffff:8.8.4.4", AgentTokenHash = Tokens.Hash(Tokens.New()) };
            var editable = new Server { Name = "legacy editable", Role = "exit", Host = "8.8.4.99", AgentTokenHash = Tokens.Hash(Tokens.New()) };
            async Task Db(Func<MayakDb, Task> action)
            {
                await using var scope = factory.Services.CreateAsyncScope();
                await action(scope.ServiceProvider.GetRequiredService<MayakDb>());
            }
            await Db(async db =>
            {
                db.Accounts.Add(owner);
                db.Sessions.Add(new Session { AccountId = owner.Id, TokenHash = Tokens.Hash(token) });
                db.Servers.AddRange(currentExit, entry, quarantine, oldAlias, editable);
                await db.SaveChangesAsync();
            });
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            async Task RoutingUnchanged(string label)
            {
                await Db(async db =>
                {
                    var old = await db.Servers.AsNoTracking().SingleAsync(s => s.Id == currentExit.Id);
                    var oldEntry = await db.Servers.AsNoTracking().SingleAsync(s => s.Id == entry.Id);
                    var quarantined = await db.Servers.AsNoTracking().SingleAsync(s => s.Id == quarantine.Id);
                    check(label, old.Active && old.Host == "9.9.9.9" && oldEntry.Host == "1.0.0.1" &&
                        oldEntry.TargetExitId == currentExit.Id && !quarantined.Active && quarantined.ProvisioningStatus == "failed", null);
                });
            }
            var aliases = new[] { "8.8.4.4", "::ffff:8.8.4.4", "::FFFF:0808:0404", "0:0:0:0:0:ffff:0808:0404",
                "[::ffff:8.8.4.4]", "134743044", "0x08080404", "010.010.04.04", "8.8.1028", "8.8.4.4." };
            foreach (var alias in aliases)
            {
                check($"canonical IPv4 endpoint alias: {alias}", ProvisioningGuards.CanonicalHostKey(alias) == "8.8.4.4", null);
                using var create = await client.PostAsJsonAsync("/api/admin/servers", new { role = "exit", host = alias });
                using var edit = await client.PatchAsJsonAsync($"/api/admin/servers/{editable.Id}", new { host = alias, active = true });
                check($"HTTP refuses duplicate POST/PATCH alias: {alias}", create.StatusCode == HttpStatusCode.Conflict && edit.StatusCode == HttpStatusCode.Conflict,
                    $"POST={(int)create.StatusCode}, PATCH={(int)edit.StatusCode}");
                await RoutingUnchanged($"refused alias preserves exit/entry: {alias}");
            }
            await Db(async db => check("refused aliases do not add rows or edit legacy host",
                await db.Servers.CountAsync() == 5 && await db.Servers.Where(s => s.Id == editable.Id).Select(s => s.Host).SingleAsync() == "8.8.4.99", null));
            foreach (var id in new[] { oldAlias.Id, quarantine.Id })
            {
                using var activation = await client.PatchAsJsonAsync($"/api/admin/servers/{id}", new { active = true });
                check("activation refuses persisted canonical duplicate without host PATCH", activation.StatusCode == HttpStatusCode.Conflict, $"status={(int)activation.StatusCode}");
                await RoutingUnchanged("persisted alias refusal preserves exit/entry");
            }
            using (var retarget = await client.PatchAsJsonAsync($"/api/admin/servers/{entry.Id}", new { targetExitId = oldAlias.Id }))
                check("entry cannot select an already persisted alias target", retarget.StatusCode == HttpStatusCode.Conflict, $"status={(int)retarget.StatusCode}");
            await RoutingUnchanged("entry alias-target refusal preserves exit/entry");
            var race = await Task.WhenAll(
                client.PostAsJsonAsync("/api/admin/servers", new { role = "exit", host = "::ffff:8.8.4.5" }),
                client.PostAsJsonAsync("/api/admin/servers", new { role = "exit", host = "8.8.4.5" }));
            try
            {
                check("concurrent canonical aliases create one row and refuse the other",
                    race.Count(r => r.StatusCode == HttpStatusCode.OK) == 1 && race.Count(r => r.StatusCode == HttpStatusCode.Conflict) == 1, null);
            }
            finally { foreach (var response in race) response.Dispose(); }
            await Db(async db => check("new manual aliases are stored as one canonical IPv4",
                (await db.Servers.AsNoTracking().Select(s => s.Host).ToListAsync()).Count(h => ProvisioningGuards.CanonicalHostKey(h) == "8.8.4.5") == 1 &&
                await db.Servers.AnyAsync(s => s.Host == "8.8.4.5" && !s.Active), null));
            await RoutingUnchanged("concurrent alias requests preserve current routing");
            using var positive = await client.PostAsJsonAsync("/api/admin/servers", new { role = "exit", host = "::ffff:9.9.9.10" });
            var created = await positive.Content.ReadFromJsonAsync<JsonNode>();
            var legitimate = created?["server"]?["id"]?.GetValue<Guid>() ?? Guid.Empty;
            check("unique legacy manual target remains supported and canonicalized", positive.StatusCode == HttpStatusCode.OK &&
                created?["server"]?["host"]?.GetValue<string>() == "9.9.9.10", null);
            using (var activation = await client.PatchAsJsonAsync($"/api/admin/servers/{legitimate}", new { active = true }))
                check("unique legitimate legacy target can still activate", activation.StatusCode == HttpStatusCode.OK, null);
            await Db(async db => check("positive activation updates routing only when unique",
                !await db.Servers.Where(s => s.Id == currentExit.Id).Select(s => s.Active).SingleAsync() &&
                await db.Servers.Where(s => s.Id == entry.Id).Select(s => s.TargetExitId).SingleAsync() == legitimate, null));
            using (var restore = await client.PatchAsJsonAsync($"/api/admin/servers/{currentExit.Id}", new { active = true }))
                check("original legitimate exit can be explicitly reselected", restore.StatusCode == HttpStatusCode.OK, null);
            await RoutingUnchanged("positive fixture returns to original routing");
        }
        finally
        {
            if (factory != null) await factory.DisposeAsync();
            foreach (var (key, value) in previous) Environment.SetEnvironmentVariable(key, value);
            NpgsqlConnection.ClearAllPools();
            await using var connection = new NpgsqlConnection(adminSettings.ConnectionString);
            await connection.OpenAsync();
            await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS {name} WITH (FORCE)", connection);
            await drop.ExecuteNonQueryAsync();
        }
    }
}
