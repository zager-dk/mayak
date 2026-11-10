using Microsoft.AspNetCore.Hosting;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Api.Provisioning;
using Mayak.Core.Agent;
using Mayak.Core.Awg;
using Mayak.Core.Crypto;
using Mayak.Core.Export;
using Mayak.Core.Models;
using Mayak.Core.Server;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using Npgsql;

// Тест API Маяка на настоящем PostgreSQL. Запуск:
// dotnet run --project tests/Mayak.ApiTest -- "Host=127.0.0.1;Port=55432;Username=postgres"
int failed = 0, passed = 0;
void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

var readinessNow = DateTime.UtcNow;
var readinessSample = new ExitEndpoint
{
    AllowNewConnections = true, CapacitySlots = 1, IdentityVersion = 4, AppliedCredentialsRevision = 7,
    ProtocolReportReceivedAt = readinessNow, ReportedIdentityVersion = 4, ReportedCredentialsRevision = 7,
    RuntimeReady = true, ConfigValid = true, SelfTestPassed = true,
};
Check("VLESS readiness принимает положительный свежий ACK", ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ProtocolReportReceivedAt = readinessNow.AddSeconds(-120);
Check("VLESS readiness включает точную границу freshness 120 s", ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ProtocolReportReceivedAt = readinessNow.AddSeconds(-121);
Check("устаревший protocol report исключает выход", !ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ProtocolReportReceivedAt = readinessNow;
readinessSample.ReportedIdentityVersion = 3;
Check("несовпадение identity version исключает выход", !ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ReportedIdentityVersion = 4;
readinessSample.ReportedCredentialsRevision = 6;
Check("неприменённая credentials revision исключает выход", !ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ReportedCredentialsRevision = 7;
readinessSample.ReportedCredentialsRevision = 8;
Check("future credentials ACK cannot pre-authorize a later membership", !ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.ReportedCredentialsRevision = 7;
readinessSample.DryRun = true;
Check("dry-run не доказывает готовность VLESS", !ClusterService.IsPoolReady(readinessSample, readinessNow));
readinessSample.DryRun = false;
readinessSample.SelfTestPassed = false;
Check("неудачный protocol self-test исключает выход", !ClusterService.IsPoolReady(readinessSample, readinessNow));
var xhttpLink = Mayak.Api.Gateway.GatewayEndpoints.BuildPoolLink(new ExitEndpoint
{
    Host = "xray.example.test", Port = 443, PublicKey = "reality-pub", Sni = "mask.example.test",
    ShortId = "abcd", Transport = "xhttp", XhttpHost = "front.example.test", XhttpPath = "/api/v1", XhttpMode = "auto",
    Fingerprint = "firefox",
}, new Device { XrayId = "stable-id", Name = "test" });
Check("pool VLESS link preserves XHTTP Reality identity and path", xhttpLink.Contains("type=xhttp") && xhttpLink.Contains("host=front.example.test") &&
      xhttpLink.Contains("path=%2Fapi%2Fv1") && xhttpLink.Contains("fp=firefox") && xhttpLink.Contains("pbk=reality-pub"));
Check("provision target validator accepts canonical public IPv4 only", ProvisioningRules.TryPublicIpv4("8.8.4.4", "https://mayaklight.ru", out _, out _) &&
    !ProvisioningRules.TryPublicIpv4("127.0.0.1", "https://mayaklight.ru", out _, out _) &&
    !ProvisioningRules.TryPublicIpv4("169.254.169.254", "https://mayaklight.ru", out _, out _) &&
    !ProvisioningRules.TryPublicIpv4("5.42.104.30", "https://mayaklight.ru", out _, out _));
const string realisticEmptySocketTable = "udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\nudp UNCONN 0 0 5.42.104.30%eth0:68 0.0.0.0:*\nudp UNCONN 0 0 *:443 *:*\nudp UNCONN 0 0 [fe80::5438:a0ff:feae:6219]%eth0:546 [::]:*\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 200 127.0.0.1:5432 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.1:18080 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:10050 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.54:53 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.1:2019 0.0.0.0:*\ntcp LISTEN 0 512 127.0.0.1:5080 0.0.0.0:*\ntcp LISTEN 0 4096 *:443 *:*\ntcp LISTEN 0 128 [::]:22 [::]:*\ntcp LISTEN 0 4096 *:80 *:*\ntcp LISTEN 0 200 [::1]:5432 [::]:*";
Check("real ss netid output reproduces legacy state-column rejection", realisticEmptySocketTable.Split('\n').All(line =>
    line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0] is not ("LISTEN" or "UNCONN")) && ProvisioningRules.ValidSocketTable(realisticEmptySocketTable));
const string protocolSocketTable = "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\ntcp LISTEN 0 128 [::]:8443 [::]:*";
Check("provision port parser validates real TCP/UDP format, IPv6 and protocol-aware occupancy", ProvisioningRules.ValidSocketTable(protocolSocketTable) &&
    ProvisioningRules.IsOccupied(protocolSocketTable, 51820, false) && ProvisioningRules.IsOccupied(protocolSocketTable, 8443, true) &&
    !ProvisioningRules.IsOccupied(protocolSocketTable, 51820, true) && !ProvisioningRules.IsOccupied(protocolSocketTable, 8443, false) &&
    ProvisioningRules.ValidSocketTable("tcp6 LISTEN 0 128 [fe80::1%eth0]:8443 [::]:*") &&
    ProvisioningRules.ValidSocketTable("tcp LISTEN 0 128 192.0.2.1%eth0:8443 [::]:*") &&
    ProvisioningRules.ValidSocketTable("tcp6 LISTEN 0 128 [fe80::1]%eth0:8443 [::]:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 128 invalid-address:* [::]:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 128 0.0.0.0:22 host.invalid:*"));
Check("provision socket parser rejects malformed, unknown and contradictory rows", !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 nope 0.0.0.0:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("sctp LISTEN 0 10 0.0.0.0:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("udp LISTEN 0 10 0.0.0.0:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 10 host.invalid:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 10 0.0.0.0:22 host.invalid:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN - 10 0.0.0.0:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("tcp6 LISTEN 0 128 127.0.0.1:22 0.0.0.0:*") &&
    !ProvisioningRules.ValidSocketTable("tcp LISTEN 0 128 [fe80::1%eth0]%eth1:22 [::]:*"));
using (var provisionSsh = new SshConnection(new SshCredentials { Host = "127.0.0.1", User = "fixture" }, cleanupStaleFiles: false, sftpOperationTimeout: TimeSpan.FromSeconds(45)))
{
    provisionSsh.Cancel();
    Check("provisioning SSH wrapper configures finite SFTP operation timeout and cancellable transport", provisionSsh.SftpOperationTimeout == TimeSpan.FromSeconds(45));
}
var healthyProbe = new ProvisioningProbeShell { SocketOutput = realisticEmptySocketTable };
Check("actual provisioning preflight accepts explicit healthy root probes", SshProvisioningBackend.InspectConnected(healthyProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
var sudoProbe = new ProvisioningProbeShell { IsRoot = false, SudoWorks = true };
Check("actual provisioning preflight accepts explicit nonroot sudo probes", SshProvisioningBackend.InspectConnected(sudoProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
foreach (var root in new[] { true, false })
foreach (var mode in new[] { "absent-tools", "empty-tools", "occupied", "docker-denied", "podman-denied", "sudo-denied" })
{
    if (root && mode == "sudo-denied") continue;
    using var executable = new GeneratedContainerProbeFixture(mode);
    var actualProbe = new ProvisioningProbeShell { IsRoot = root, ContainerCommandRunner = executable.Run };
    var actual = SshProvisioningBackend.InspectConnected(actualProbe, new ProvisioningPlan(51820, 8443, false, "fixture"));
    // Занятый сервер теперь допускается к установке с перезаписью: Supported и Occupied.
    var expectedSupported = mode is "absent-tools" or "empty-tools" or "occupied";
    Check($"generated POSIX container probe executes: root={root}, {mode}",
        actual.Supported == expectedSupported && actual.Occupied == (mode == "occupied") && executable.Result != null &&
        (mode.EndsWith("denied", StringComparison.Ordinal) ? !executable.Result.Ok : executable.Result.Ok) &&
        executable.SudoUsed == !root && !executable.Result.Error.Contains("bad substitution", StringComparison.OrdinalIgnoreCase),
        $"exit={executable.Result?.ExitCode}");
}
var deniedProbe = new ProvisioningProbeShell { IsRoot = false, SudoWorks = true };
deniedProbe.FailFragments.Add("docker podman");
Check("actual provisioning preflight fails closed on denied container inspection", !SshProvisioningBackend.InspectConnected(deniedProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
foreach (var failedProbeCommand in new[] { "cat /etc/os-release", "uname -m", "ss -H -lntu", "for r in docker podman", "/etc/mayak/agent.json", "systemctl list-units", "ip -o link show", "command -v wg" })
{
    var failedProbe = new ProvisioningProbeShell();
    failedProbe.FailFragments.Add(failedProbeCommand);
    Check($"actual preflight rejects failed command: {failedProbeCommand}", !SshProvisioningBackend.InspectConnected(failedProbe,
        new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
}
var occupiedProbe = new ProvisioningProbeShell { SocketOutput = "tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*" };
Check("actual provisioning preflight rejects occupied requested TCP port", !SshProvisioningBackend.InspectConnected(occupiedProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
var occupiedUdpProbe = new ProvisioningProbeShell { SocketOutput = "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*" };
Check("actual provisioning preflight rejects occupied requested UDP port", !SshProvisioningBackend.InspectConnected(occupiedUdpProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
var contradictoryFamilyProbe = new ProvisioningProbeShell { SocketOutput = "tcp6 LISTEN 0 128 127.0.0.1:22 0.0.0.0:*" };
Check("actual provisioning preflight rejects IPv6 netid with IPv4 endpoints", !SshProvisioningBackend.InspectConnected(contradictoryFamilyProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
var contradictoryZoneProbe = new ProvisioningProbeShell { SocketOutput = "tcp LISTEN 0 128 [fe80::1%eth0]%eth1:22 [::]:*" };
Check("actual provisioning preflight rejects endpoints with duplicate IPv6 zones", !SshProvisioningBackend.InspectConnected(contradictoryZoneProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")).Supported);
var vpnProbe = new ProvisioningProbeShell { LinkOutput = "1: lo: <LOOPBACK> mtu 65536 state UNKNOWN\n2: awg0: <POINTOPOINT> mtu 1420 state UP" };
Check("actual provisioning preflight marks an existing VPN interface as occupied (overwrite required)", SshProvisioningBackend.InspectConnected(vpnProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")) is { Supported: true, Occupied: true });
var artifactProbe = new ProvisioningProbeShell { ArtifactOutput = "MAYAK_EXISTING_ARTIFACT" };
Check("actual provisioning preflight marks existing server artifacts as occupied (overwrite required)", SshProvisioningBackend.InspectConnected(artifactProbe,
    new ProvisioningPlan(51820, 8443, false, "fixture")) is { Supported: true, Occupied: true });
var agentStageShell = new RecordingProvisioningShell { IsRoot = false, Sudo = "sudo -n " };
var stageContext = new ProvisioningInstallContext(Guid.NewGuid(), "fixture", new ProvisioningCredentials("8.8.4.4", 22, "deploy", "fixture-password", "SHA256:fixture"),
    new ProvisioningPlan(51820, 8443, false, "fixture"), null, "fixture-agent-token", "https://mayaklight.ru");
await SshProvisioningBackend.InstallAgentAsync(agentStageShell, stageContext, "https://mayaklight.ru", _ => Task.CompletedTask, CancellationToken.None);
Check("actual agent staging elevates every privileged command for nonroot sudo", agentStageShell.Commands.Count > 0 &&
    agentStageShell.Commands.All(c => c.StartsWith("sudo -n ", StringComparison.Ordinal)) &&
    agentStageShell.Commands.Any(c => c.Contains("mkdir -p", StringComparison.Ordinal)) &&
    agentStageShell.Commands.Any(c => c.Contains("curl -fsSL", StringComparison.Ordinal)) &&
    agentStageShell.Commands.Any(c => c.Contains("systemctl daemon-reload", StringComparison.Ordinal)) &&
    agentStageShell.Files.Any(f => f.Path == "/etc/mayak/agent.json" && f.Mode == "600") &&
    agentStageShell.Files.Any(f => f.Path == "/etc/systemd/system/mayak-agent.service" && f.Mode == "644"));

var server = args.ElementAtOrDefault(0) ?? "Host=127.0.0.1;Port=55432;Username=postgres";
await ProvisioningAliasFixture.RunAsync(server, Check);
var upgradeDbName = "mayak_upgrade_" + Guid.NewGuid().ToString("N")[..8];
await using (var adminConnection = new NpgsqlConnection($"{server};Database=postgres"))
{
    await adminConnection.OpenAsync();
    await using var create = new NpgsqlCommand($"CREATE DATABASE {upgradeDbName};", adminConnection);
    await create.ExecuteNonQueryAsync();
}
try
{
    var upgradeOptions = new DbContextOptionsBuilder<MayakDb>().UseNpgsql($"{server};Database={upgradeDbName}").Options;
    await using var upgradeDb = new MayakDb(upgradeOptions);
    var migrator = upgradeDb.GetService<IMigrator>();
    await migrator.MigrateAsync("20261028170000_DeviceSubscriptions");
    var legacyAccountId = Guid.Parse("41200000-0000-0000-0000-000000000001");
    var legacyDeviceId = Guid.Parse("41200000-0000-0000-0000-000000000003");
    const string legacyPublicKey = "legacy-public-key-preservation-fixture";
    const string legacyXrayId = "41200000-0000-0000-0000-000000000002";
    const string legacyIp = "10.8.1.44";
    async Task SeedLegacySchemaAsync()
    {
        await using var fixtureConnection = new NpgsqlConnection($"{server};Database={upgradeDbName}");
        await fixtureConnection.OpenAsync();
        await using var insertAccount = new NpgsqlCommand("""
            INSERT INTO "Accounts" ("Id", "Name", "Role", "Enabled", "Note", "CreatedAt", "MaxDevices", "DownMbps", "UpMbps", "Legacy", "AppKey")
            VALUES (@id, 'upgrade fixture', 'user', true, '', @created, 3, 35, 35, false, 'fixture-app-key');
            """, fixtureConnection);
        insertAccount.Parameters.AddWithValue("id", legacyAccountId);
        insertAccount.Parameters.AddWithValue("created", DateTime.UtcNow);
        await insertAccount.ExecuteNonQueryAsync();
        await using var insertDevice = new NpgsqlCommand("""
            INSERT INTO "Devices" ("Id", "AccountId", "Name", "Kind", "AwgPublicKey", "Ip", "XrayId", "Enabled", "CreatedAt", "RxBytes", "TxBytes", "SubscriptionTokenHash")
            VALUES (@id, @account, 'legacy device', 'Android', @public_key, @ip, @xray_id, true, @created, 1234, 5678, NULL);
            """, fixtureConnection);
        insertDevice.Parameters.AddWithValue("id", legacyDeviceId);
        insertDevice.Parameters.AddWithValue("account", legacyAccountId);
        insertDevice.Parameters.AddWithValue("public_key", legacyPublicKey);
        insertDevice.Parameters.AddWithValue("ip", legacyIp);
        insertDevice.Parameters.AddWithValue("xray_id", legacyXrayId);
        insertDevice.Parameters.AddWithValue("created", DateTime.UtcNow);
        await insertDevice.ExecuteNonQueryAsync();
        await using var insertCluster = new NpgsqlCommand("""
            INSERT INTO "Cluster" ("Id", "AwgJson", "AwgServerPrivateKey", "XrayJson", "XrayPrivateKey", "Dns1", "Dns2", "PublicHost", "Title", "Revision")
            VALUES (1, 'legacy-awg-json-fixture', 'fixture-legacy-private-key', NULL, NULL, '1.1.1.1', '1.0.0.1', '', 'legacy title', 29);
            """, fixtureConnection);
        await insertCluster.ExecuteNonQueryAsync();
    }
    await SeedLegacySchemaAsync();
    await migrator.MigrateAsync();
    upgradeDb.ChangeTracker.Clear();
    var preservedDevice = await upgradeDb.Devices.SingleAsync(d => d.AwgPublicKey == legacyPublicKey);
    var preservedAccount = await upgradeDb.Accounts.SingleAsync(a => a.Id == legacyAccountId);
    var preservedCluster = await upgradeDb.Cluster.SingleAsync(c => c.Id == 1);
    Check("upgrade from API-01 schema preserves legacy device/account/cluster values and adds empty pool", preservedDevice.Id == legacyDeviceId &&
        preservedDevice.Ip == legacyIp && preservedDevice.XrayId == legacyXrayId && preservedDevice.RxBytes == 1234 && preservedDevice.TxBytes == 5678 &&
        preservedDevice.ServiceProtocol == null && preservedDevice.ExitEndpointId == null && preservedAccount.AppKey == "fixture-app-key" &&
        preservedCluster.AwgJson == "legacy-awg-json-fixture" && preservedCluster.AwgServerPrivateKey == "fixture-legacy-private-key" && preservedCluster.Revision == 29 &&
        !await upgradeDb.ExitEndpoints.AnyAsync());

    // Also upgrade an already-populated pool from the immediately preceding schema.
    // Start from a fresh database: later migrations (e.g. EmailPasswordCredentials) deliberately
    // keep data on rollback, so a down-then-up round trip is not a supported path.
    await upgradeDb.Database.EnsureDeletedAsync();
    NpgsqlConnection.ClearAllPools();
    upgradeDb.ChangeTracker.Clear();
    await migrator.MigrateAsync("20261028170000_DeviceSubscriptions");
    await SeedLegacySchemaAsync();
    await migrator.MigrateAsync("20261028210000_VlessPool");
    var upgradeServerId = Guid.NewGuid();
    var upgradeEndpointId = Guid.NewGuid();
    await using (var fixtureConnection = new NpgsqlConnection($"{server};Database={upgradeDbName}"))
    {
        await fixtureConnection.OpenAsync();
        await using var seedPool = new NpgsqlCommand("""
            INSERT INTO "Servers" ("Id","Name","Role","Host","City","Country","CountryCode","Fact","AgentTokenHash","Active","CreatedAt")
            VALUES (@server,'pool upgrade','exit','upgrade.example.test','','','','','upgrade-agent-hash',false,@now);
            INSERT INTO "ExitEndpoints" ("Id","ServerId","Host","Port","PublicKey","Sni","ShortId","Flow","Transport","Fingerprint","XhttpPath","XhttpHost","XhttpMode",
                "IdentityVersion","AllowNewConnections","CapacitySlots","AppliedCredentialsRevision","ProtocolReportReceivedAt","ReportedIdentityVersion","ReportedCredentialsRevision",
                "RuntimeReady","ConfigValid","SelfTestPassed","DryRun","OccupiedSlots")
            VALUES (@endpoint,@server,'upgrade.example.test',443,'upgrade-public-key','mask.example.test','abcd','','tcp','chrome','/','','auto',
                3,true,4,9,@now,3,9,true,true,true,false,1);
            UPDATE "Devices" SET "ServiceProtocol"='vless',"ExitEndpointId"=@endpoint,"CredentialsRevision"=9 WHERE "Id"=@device;
            """, fixtureConnection);
        seedPool.Parameters.AddWithValue("server", upgradeServerId);
        seedPool.Parameters.AddWithValue("endpoint", upgradeEndpointId);
        seedPool.Parameters.AddWithValue("device", legacyDeviceId);
        seedPool.Parameters.AddWithValue("now", DateTime.UtcNow);
        await seedPool.ExecuteNonQueryAsync();
    }
    await migrator.MigrateAsync();
    upgradeDb.ChangeTracker.Clear();
    var upgradedEndpoint = await upgradeDb.ExitEndpoints.SingleAsync();
    var provisionMigrationServer = await upgradeDb.Servers.SingleAsync(s => s.Id == upgradeServerId);
    Check("pool snapshot migration preserves populated pool identity/revision/occupied slots", upgradedEndpoint.IdentityVersion == 3 &&
        upgradedEndpoint.AppliedCredentialsRevision == 9 && upgradedEndpoint.OccupiedSlots == 1 && upgradedEndpoint.PublicKey == "upgrade-public-key");
    Check("provision migration preserves existing servers and leaves them non-provisioned", provisionMigrationServer.Host == "upgrade.example.test" &&
        provisionMigrationServer.ProvisioningStatus == null && provisionMigrationServer.TrustedHostFingerprint == null && !provisionMigrationServer.ProvisionIdentityMatched);
    var upgradeCluster = new ClusterService(upgradeDb);
    var upgradeServer = await upgradeDb.Servers.SingleAsync(s => s.Id == upgradeServerId);
    var upgradedState = await upgradeCluster.StateForAsync(upgradeServer, CancellationToken.None);
    Check("first populated-pool reconciliation invalidates pre-snapshot ACK without changing credentials", upgradedState.PoolEndpoint?.DesiredCredentialsRevision == 10 &&
        upgradedState.PoolDevices.Single().XrayId == legacyXrayId && upgradedEndpoint.ProtocolReportReceivedAt == null && upgradedEndpoint.OccupiedSlots == 1);
    var repeatedUpgradeState = await upgradeCluster.StateForAsync(upgradeServer, CancellationToken.None);
    Check("upgraded pool reconciliation is stable on unchanged polls", repeatedUpgradeState.PoolEndpoint?.DesiredCredentialsRevision == 10 &&
        (await upgradeDb.Devices.SingleAsync()).AwgPublicKey == legacyPublicKey && (await upgradeDb.Devices.SingleAsync()).Ip == legacyIp);
}
finally
{
    await using var adminConnection = new NpgsqlConnection($"{server};Database=postgres");
    await adminConnection.OpenAsync();
    await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS {upgradeDbName} WITH (FORCE);", adminConnection);
    await drop.ExecuteNonQueryAsync();
}
var dbName = "mayak_test_" + Guid.NewGuid().ToString("N")[..8];
var cs = $"{server};Database={dbName}";
Environment.SetEnvironmentVariable("MAYAK_ConnectionStrings__Db", cs);
Environment.SetEnvironmentVariable("MAYAK_Telegram__Polling", "false");
Environment.SetEnvironmentVariable("MAYAK_Probes__Enabled", "false");
Environment.SetEnvironmentVariable("MAYAK_PublicUrl", "https://mayaklight.ru");
var (gwPriv, gwPub) = Mayak.Core.Gateway.GatewayCrypto.GenerateKeyPair();
var gwKeyPath = Path.Combine(Path.GetTempPath(), $"mayak-gw-{dbName}.pem");
File.WriteAllText(gwKeyPath, gwPriv);
Environment.SetEnvironmentVariable("MAYAK_Gateway__PrivateKeyPath", gwKeyPath);
using var gwRsa = System.Security.Cryptography.RSA.Create();
gwRsa.ImportFromPem(gwPub);

var fakeTg = new FakeTelegram();
var fakeProvisioning = new FakeProvisioningBackend();
var observedLogs = new ConcurrentQueue<string>();
await using var factory = new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b =>
{
    b.UseContentRoot(AppContext.BaseDirectory);
    b.ConfigureLogging(logging => logging.AddProvider(new CaptureLoggerProvider(observedLogs)));
    b.ConfigureTestServices(s =>
    {
        s.AddSingleton(new TelegramOptions { Token = "test" });
        s.AddSingleton<TelegramClient>(fakeTg);
        s.RemoveAll<IProvisioningBackend>();
        s.AddSingleton<IProvisioningBackend>(fakeProvisioning);
    });
});
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
    async Task<JsonNode> GatewayRequest(object payload)
    {
        var (body, session) = Mayak.Core.Gateway.GatewayCrypto.SealRequest(JsonSerializer.Serialize(payload), gwRsa);
        using var response = await http.PostAsync("/gw/v1/config", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        return JsonNode.Parse(Mayak.Core.Gateway.GatewayCrypto.OpenResponse(await response.Content.ReadAsByteArrayAsync(), session))!;
    }
    AgentReport PoolReport(AgentPoolEndpoint desired, bool ready = true) => new()
    {
        Protocol = "vless", IdentityVersion = desired.IdentityVersion, CredentialsRevision = desired.DesiredCredentialsRevision,
        RuntimeReady = ready, ConfigValid = ready, SelfTestPassed = ready,
    };
    var nativeFixtureDirectory = Environment.GetEnvironmentVariable("MAYAK_NATIVE_POOL_FIXTURE_DIR");
    var nativeCases = new JsonArray();
    async Task CaptureNativeFixture(string name, JsonNode emittedRoot, Guid endpointId, Guid deviceId, string? emittedNative = null)
    {
        if (string.IsNullOrEmpty(nativeFixtureDirectory)) return;
        Directory.CreateDirectory(nativeFixtureDirectory);
        var output = Path.Combine(nativeFixtureDirectory, name + ".json");
        await File.WriteAllTextAsync(output, emittedRoot.ToJsonString());
        string? nativeOutput = null;
        if (emittedNative != null)
        {
            nativeOutput = Path.Combine(nativeFixtureDirectory, name + ".native.json");
            await File.WriteAllTextAsync(nativeOutput, emittedNative);
        }
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var endpoint = await db.ExitEndpoints.SingleAsync(e => e.Id == endpointId);
        var device = await db.Devices.SingleAsync(d => d.Id == deviceId);
        nativeCases.Add(new JsonObject
        {
            ["name"] = name, ["path"] = output, ["nativePath"] = nativeOutput, ["host"] = endpoint.Host, ["port"] = endpoint.Port,
            ["uuid"] = device.XrayId, ["publicKey"] = endpoint.PublicKey, ["sni"] = endpoint.Sni,
            ["shortId"] = endpoint.ShortId, ["fingerprint"] = endpoint.Fingerprint, ["flow"] = endpoint.Flow,
            ["network"] = endpoint.Transport == "xhttp" ? "xhttp" : "tcp", ["xhttpPath"] = endpoint.XhttpPath,
            ["xhttpHost"] = string.IsNullOrEmpty(endpoint.XhttpHost) ? endpoint.Sni : endpoint.XhttpHost, ["xhttpMode"] = endpoint.XhttpMode,
        });
        await File.WriteAllTextAsync(Path.Combine(nativeFixtureDirectory, "manifest.json"), nativeCases.ToJsonString());
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

    Console.WriteLine("Установка нового пустого сервера:");
    Guid quarantinedProvisionId;
    const string quarantineToken = "quarantine-token";
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        quarantinedProvisionId = Guid.NewGuid();
        provisionDb.Servers.Add(new Server { Id = quarantinedProvisionId, Name = "Provision quarantine fixture", Role = "exit", Host = "8.8.8.8", AgentTokenHash = Tokens.Hash(quarantineToken), ProvisioningStatus = "awaiting_agent" });
        await provisionDb.SaveChangesAsync();
    }
    Check("PATCH не активирует сервер до установки и совпадения identity", (await owner.PatchAsJsonAsync($"/api/admin/servers/{quarantinedProvisionId}", new { active = true })).StatusCode == HttpStatusCode.Conflict);
    const string provisionSecret = "provision-password-test-value";
    const string provisionFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    Check("анонимный provisioning закрыт", (await http.PostAsJsonAsync("/api/admin/provision/host-key", new { host = "8.8.4.4", port = 22 })).StatusCode == HttpStatusCode.Unauthorized);
    Check("пользователю provisioning закрыт", (await As(guestToken).PostAsJsonAsync("/api/admin/provision/host-key", new { host = "8.8.4.4", port = 22 })).StatusCode == HttpStatusCode.Forbidden);
    var fpResponse = await owner.PostAsJsonAsync("/api/admin/provision/host-key", new { host = "8.8.4.4", port = 22 });
    Check("fingerprint берётся до отправки SSH-пароля", fpResponse.IsSuccessStatusCode &&
        (await fpResponse.Content.ReadFromJsonAsync<JsonNode>())?["fingerprint"]?.GetValue<string>() == provisionFingerprint);
    Check("опасный loopback target отклоняется до SSH", (await owner.PostAsJsonAsync("/api/admin/provision/host-key", new { host = "127.0.0.1", port = 22 })).StatusCode == HttpStatusCode.BadRequest);
    var untrustedInspect = await owner.PostAsJsonAsync("/api/admin/provision/inspect", new { host = "8.8.4.4", port = 22, user = "root", password = "probe-secret", trustedFingerprint = provisionFingerprint, trustFingerprint = false });
    Check("credentialed probe запрещён без явного подтверждения fingerprint", untrustedInspect.StatusCode == HttpStatusCode.BadRequest &&
        !observedLogs.Any(x => x.Contains("probe-secret", StringComparison.Ordinal)));

    ClusterIdentity provisionIdentity;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        provisionIdentity = await provisionDb.Cluster.AsNoTracking().SingleAsync(c => c.Id == 1);
    }
    var awgIdentity = ClusterService.AwgOf(provisionIdentity);
    var xrayIdentity = ClusterService.XrayOf(provisionIdentity)!;
    var provisionProof = new ProvisioningRuntimeProof { AwgRunning = true, XrayRunning = true, ConfigurationLoaded = true, PostApplyCheckPassed = true };
    var provisioningReadinessNow = DateTime.UtcNow;
    var readyReport = new AgentReport { AppliedRevision = provisionIdentity.Revision, ProvisioningProof = provisionProof };
    var readyCandidate = new Server
    {
        ProvisioningStatus = "installed", ProvisionIdentityMatched = true,
        ProvisioningIdentityHash = ProvisioningPlanner.IdentityHash(provisionIdentity),
        ProvisioningConfirmedRevision = provisionIdentity.Revision, ProvisioningConfirmedAt = provisioningReadinessNow,
        LastSeen = provisioningReadinessNow, LastReport = JsonSerializer.Serialize(readyReport),
    };
    Check("fresh exact provisioning identity and runtime proof pass readiness", ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    readyCandidate.LastReport = JsonSerializer.Serialize(new AgentReport { AppliedRevision = long.MaxValue, ProvisioningProof = provisionProof });
    Check("future revision ACK cannot pass provisioning readiness", !ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    readyCandidate.LastReport = JsonSerializer.Serialize(new AgentReport { AppliedRevision = provisionIdentity.Revision, DryRun = true, ProvisioningProof = provisionProof });
    Check("dry-run report cannot pass provisioning readiness", !ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    readyCandidate.LastReport = JsonSerializer.Serialize(new AgentReport { AppliedRevision = provisionIdentity.Revision, Error = "fixture failure", ProvisioningProof = provisionProof });
    Check("failed runtime report cannot pass provisioning readiness", !ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    readyCandidate.LastReport = JsonSerializer.Serialize(readyReport);
    readyCandidate.ProvisioningConfirmedAt = provisioningReadinessNow.AddSeconds(6);
    Check("future provision confirmation timestamp cannot pass readiness", !ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    readyCandidate.ProvisioningConfirmedAt = provisioningReadinessNow;
    readyCandidate.ProvisioningConfirmedRevision = provisionIdentity.Revision + 1;
    Check("future confirmed cluster revision cannot pass readiness", !ProvisioningGuards.IsReady(readyCandidate, provisionIdentity, provisioningReadinessNow));
    var changedAwg = ClusterService.AwgOf(provisionIdentity);
    changedAwg.ServerPublicKey = "changed-fixture-key";
    var mismatchHello = await As(quarantineToken).PostAsJsonAsync(AgentPaths.Hello, new AgentHello
    {
        Version = "mismatch-fixture",
        Identity = new AgentIdentity { Awg = changedAwg, AwgServerPrivateKey = provisionIdentity.AwgServerPrivateKey,
            Xray = ClusterService.XrayOf(provisionIdentity), XrayPrivateKey = provisionIdentity.XrayPrivateKey,
            Dns1 = provisionIdentity.Dns1, Dns2 = provisionIdentity.Dns2, Title = provisionIdentity.Title },
    }, json);
    Check("mismatched agent identity is rejected and quarantined", mismatchHello.StatusCode == HttpStatusCode.Conflict);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var mismatchServer = await provisionDb.Servers.SingleAsync(s => s.Id == quarantinedProvisionId);
        Check("identity mismatch clears provisioning readiness", mismatchServer.ProvisioningStatus == "failed" && !mismatchServer.ProvisionIdentityMatched && mismatchServer.ProvisioningConfirmedRevision == null);
    }

    var revocableAdminId = Guid.NewGuid();
    var revocableAdminToken = Tokens.New();
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        provisionDb.Accounts.Add(new Account { Id = revocableAdminId, Name = "Revoked during inspect", Role = Roles.Admin, Enabled = true });
        provisionDb.Sessions.Add(new Session { AccountId = revocableAdminId, TokenHash = Tokens.Hash(revocableAdminToken) });
        await provisionDb.SaveChangesAsync();
    }
    fakeProvisioning.BeforeInspect = async () =>
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var actor = await provisionDb.Accounts.SingleAsync(a => a.Id == revocableAdminId);
        actor.Enabled = false;
        actor.Role = Roles.User;
        await provisionDb.SaveChangesAsync();
    };
    var revokedStart = await As(revocableAdminToken).PostAsJsonAsync("/api/admin/provision/start", new
    {
        host = "8.8.4.6", port = 22, user = "root", password = provisionSecret,
        trustedFingerprint = provisionFingerprint, trustFingerprint = true, name = "Revoked probe", city = "Test", country = "Test",
        awgPort = awgIdentity.Port, xrayPort = xrayIdentity.Port, confirmBlankServer = true,
    });
    fakeProvisioning.BeforeInspect = null;
    Check("аккаунт повторно проверяется после SSH inspection до записи job", revokedStart.StatusCode == HttpStatusCode.Forbidden);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        Check("отозванный actor не оставляет поставленный в очередь сервер", !await provisionDb.Servers.AnyAsync(s => s.Host == "8.8.4.6"));
    }

    fakeProvisioning.Install = async (ctx, progress, ct) =>
    {
        await progress("awaiting_agent");
        using var provisionAgent = As(ctx.AgentToken);
        var identity = new AgentIdentity
        {
            Awg = ClusterService.AwgOf(provisionIdentity), AwgServerPrivateKey = provisionIdentity.AwgServerPrivateKey,
            Xray = ClusterService.XrayOf(provisionIdentity), XrayPrivateKey = provisionIdentity.XrayPrivateKey,
            Dns1 = provisionIdentity.Dns1, Dns2 = provisionIdentity.Dns2, Title = provisionIdentity.Title,
        };
        var helloResponse = await provisionAgent.PostAsJsonAsync(AgentPaths.Hello, new AgentHello { Version = "fake-installed", Identity = identity }, json, ct);
        if (!helloResponse.IsSuccessStatusCode) throw new InvalidOperationException("Agent identity handshake rejected");
        var desired = await provisionAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json, ct) ?? throw new InvalidOperationException("Agent state unavailable");
        using var reportResponse = await provisionAgent.PostAsJsonAsync(AgentPaths.Report, new AgentReport
        {
            AppliedRevision = desired.Revision,
            ProvisioningProof = new ProvisioningRuntimeProof { AwgRunning = true, XrayRunning = true, ConfigurationLoaded = true, PostApplyCheckPassed = true },
        }, json, ct);
        if (!reportResponse.IsSuccessStatusCode) throw new InvalidOperationException("Agent report rejected");
    };
    var startResponse = await owner.PostAsJsonAsync("/api/admin/provision/start", new
    {
        host = "8.8.4.4", port = 22, user = "root", password = provisionSecret,
        trustedFingerprint = provisionFingerprint, trustFingerprint = true,
        name = "Provision test", city = "Test", country = "Test", awgPort = awgIdentity.Port, xrayPort = xrayIdentity.Port,
        confirmBlankServer = true,
    });
    var acceptedProvision = await startResponse.Content.ReadFromJsonAsync<JsonNode>();
    Check("подтверждённая пустая установка принимается без возврата SSH-пароля", startResponse.StatusCode == HttpStatusCode.Accepted &&
        !acceptedProvision!.ToJsonString().Contains(provisionSecret, StringComparison.Ordinal));
    Check("повторный start для уже зарезервированного IP отклоняется", (await owner.PostAsJsonAsync("/api/admin/provision/start", new
    {
        host = "8.8.4.4", port = 22, user = "root", password = provisionSecret,
        trustedFingerprint = provisionFingerprint, trustFingerprint = true, name = "Duplicate", awgPort = awgIdentity.Port,
        xrayPort = xrayIdentity.Port, confirmBlankServer = true,
    })).StatusCode == HttpStatusCode.Conflict);
    var provisionId = acceptedProvision!["serverId"]!.GetValue<Guid>();
    JsonNode? provisionJob = null;
    for (var i = 0; i < 40; i++)
    {
        provisionJob = await owner.GetFromJsonAsync<JsonNode>($"/api/admin/provision/jobs/{provisionId}");
        if (provisionJob?["provisioningStatus"]?.GetValue<string>() is "installed" or "failed") break;
        await Task.Delay(100);
    }
    Check("агент подтвердил identity и применил ревизию; сервер остался неактивным",
        provisionJob?["provisioningStatus"]?.GetValue<string>() == "installed" && provisionJob["provisionIdentityMatched"]?.GetValue<bool>() == true && provisionJob["active"]?.GetValue<bool>() == false);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var provisionServer = await provisionDb.Servers.SingleAsync(s => s.Id == provisionId);
        var passwordAbsentFromServer = !JsonSerializer.Serialize(provisionServer).Contains(provisionSecret, StringComparison.Ordinal);
        var auditDetails = await provisionDb.Audit.Select(a => a.Details).ToListAsync();
        var passwordAbsentFromAudit = auditDetails.All(d => !d.Contains(provisionSecret, StringComparison.Ordinal));
        var passwordAbsentFromLogs = !observedLogs.Any(x => x.Contains(provisionSecret, StringComparison.Ordinal));
        Check("SSH-пароль не сохраняется в сервере, аудите или логах", passwordAbsentFromServer && passwordAbsentFromAudit && passwordAbsentFromLogs,
            $"server={passwordAbsentFromServer}, audit={passwordAbsentFromAudit}, logs={passwordAbsentFromLogs}");
    }
    Check("после установки новый сервер по умолчанию остаётся неактивным", provisionJob?["active"]?.GetValue<bool>() == false);
    Check("зарегистрированный сервер нельзя добавить второй раз", (await owner.PostAsJsonAsync("/api/admin/provision/host-key", new { host = "8.8.4.4", port = 22 })).StatusCode == HttpStatusCode.Conflict);
    Check("legacy manual server creation cannot duplicate a provisioned target", (await owner.PostAsJsonAsync("/api/admin/servers", new
    {
        role = "exit", host = "8.8.4.4", name = "Quarantine bypass", city = "Test", country = "Test",
    })).StatusCode == HttpStatusCode.Conflict);
    Check("provisioned target host cannot be retargeted to launder quarantine", (await owner.PatchAsJsonAsync($"/api/admin/servers/{provisionId}", new { host = "8.8.8.8" })).StatusCode == HttpStatusCode.Conflict);

    string disabledAdminToken = Tokens.New();
    Guid disabledAdminId = Guid.NewGuid();
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        provisionDb.Accounts.Add(new Account { Id = disabledAdminId, Name = "Disabled provision admin", Role = Roles.Admin, Enabled = false });
        provisionDb.Sessions.Add(new Session { AccountId = disabledAdminId, TokenHash = Tokens.Hash(disabledAdminToken), CreatedAt = DateTime.UtcNow });
        await provisionDb.SaveChangesAsync();
    }
    Check("disabled admin cannot activate a provisioned candidate", (await As(disabledAdminToken).PatchAsJsonAsync($"/api/admin/servers/{provisionId}", new { active = true })).StatusCode == HttpStatusCode.Forbidden);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var candidate = await provisionDb.Servers.SingleAsync(s => s.Id == provisionId);
        candidate.LastSeen = DateTime.UtcNow.AddDays(-2);
        await provisionDb.SaveChangesAsync();
    }
    Check("stale provision readiness cannot activate and leaves the existing exit enabled", (await owner.PatchAsJsonAsync($"/api/admin/servers/{provisionId}", new { active = true })).StatusCode == HttpStatusCode.Conflict);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var provisionDb = scope.ServiceProvider.GetRequiredService<MayakDb>();
        Check("failed activation preserves the previous active exit", await provisionDb.Servers.AnyAsync(s => s.Id != provisionId && s.Role == ServerRoles.Exit && s.Active));
    }

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
    Check("готовые файлы и с входом ведут на активный выход", JsonNode.Parse(VpnKeyCodec.Decode(filesViaEntry!["vpnKey"]!.GetValue<string>()))?["hostName"]?.GetValue<string>() == "45.131.185.211"
          && filesViaEntry["conf"]!.GetValue<string>().Contains("Endpoint = 45.131.185.211:41234"));
    var clusterView = await owner.GetFromJsonAsync<JsonNode>("/api/admin/cluster");
    Check("админка показывает адрес готовых файлов отдельно от адреса входа", clusterView?["accessHost"]?.GetValue<string>() == "45.131.185.211"
          && clusterView["effectiveHost"]?.GetValue<string>() == "5.42.104.30", clusterView?.ToJsonString());

    Console.WriteLine("Кабинет на сайте:");
    var page = await http.GetStringAsync("/my/");
    Check("страница кабинета открывается по /my/", page.Contains("Войти через Telegram"));
    foreach (var staticPath in new[] { "/", "/my/", "/admin/" })
    {
        using var staticResp = await http.GetAsync(staticPath);
        Check($"страница {staticPath}: браузер сверяет копию с сервером (no-cache)", staticResp.IsSuccessStatusCode && staticResp.Headers.CacheControl?.NoCache == true,
            staticResp.Headers.CacheControl?.ToString());
    }
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
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{mamaId}", new { enabled = true, paidUntil = DateTime.UtcNow.AddDays(30) });
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

    var parallelAccount = (await (await owner.PostAsJsonAsync("/api/admin/accounts", new { name = "Параллельные проверки" })).Content.ReadFromJsonAsync<JsonNode>())!;
    var parallelId = parallelAccount["id"]!.GetValue<string>();
    var telegramRaceUrl = (await (await owner.PostAsync($"/api/admin/accounts/{parallelId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>();
    var telegramRaceCode = telegramRaceUrl.Split("invite=")[1];
    var telegramRaceRequestId = Tokens.New(18);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.LoginRequests.Add(new LoginRequest { Id = telegramRaceRequestId, InviteHash = Tokens.Hash(telegramRaceCode), ReturnPath = "/my/" });
        await db.SaveChangesAsync();
    }
    var directRaceTask = http.PostAsJsonAsync("/api/auth/invite", new { invite = telegramRaceCode });
    var telegramRaceTask = Say(33333, "/start " + telegramRaceRequestId, "Race");
    await Task.WhenAll(directRaceTask, telegramRaceTask);
    var directRaceResponse = await directRaceTask;
    bool telegramClaimed;
    bool raceInviteUsed;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        telegramClaimed = (await db.LoginRequests.SingleAsync(x => x.Id == telegramRaceRequestId)).AccountId == Guid.Parse(parallelId);
        raceInviteUsed = (await db.Invites.SingleAsync(x => x.CodeHash == Tokens.Hash(telegramRaceCode))).UsedAt != null;
    }
    Check("прямой и Telegram invite атомарно соревнуются за один код", raceInviteUsed &&
          (directRaceResponse.StatusCode == HttpStatusCode.OK) != telegramClaimed);
    var parallelCode = (await (await owner.PostAsync($"/api/admin/accounts/{parallelId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>().Split("invite=")[1];
    var inviteAttempts = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => http.PostAsJsonAsync("/api/auth/invite", new { invite = parallelCode })));
    Check("параллельный invite выдаёт ровно один сеанс", inviteAttempts.Count(x => x.StatusCode == HttpStatusCode.OK) == 1 && inviteAttempts.Count(x => x.StatusCode == HttpStatusCode.Gone) == 2);
    Check("ответ invite запрещает кеширование", inviteAttempts.Single(x => x.StatusCode == HttpStatusCode.OK).Headers.CacheControl?.NoStore == true);
    var parallelToken = (await inviteAttempts.Single(x => x.StatusCode == HttpStatusCode.OK).Content.ReadFromJsonAsync<JsonNode>())!["token"]!.GetValue<string>();
    var parallelUser = As(parallelToken);
    var parallelAppKeys = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => parallelUser.GetFromJsonAsync<JsonNode>("/api/app-key")));
    Check("конкурентная генерация app-key возвращает один ключ", parallelAppKeys.Select(x => x!["key"]!.GetValue<string>()).Distinct().Count() == 1);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var account = await db.Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId));
        account.AppKey = null;
        await db.SaveChangesAsync();
    }
    var resetRace = await Task.WhenAll(
        Task.WhenAll(Enumerable.Range(0, 8).Select(_ => parallelUser.GetAsync("/api/app-key"))),
        Task.WhenAll(Enumerable.Range(0, 2).Select(_ => parallelUser.PostAsync("/api/app-key/reset", null))));
    var lazyResponses = resetRace[0];
    var resetResponses = resetRace[1];
    var resetFinalKey = (await parallelUser.GetFromJsonAsync<JsonNode>("/api/app-key"))!["key"]!.GetValue<string>();
    string persistedAppKey;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        persistedAppKey = (await db.Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId))).AppKey!;
    }
    var persistedKeyJson = JsonNode.Parse(VpnKeyCodec.Decode(resetFinalKey));
    Check("lazy app-key GET и reset concurrent сохраняют ключ из БД", lazyResponses.All(x => x.IsSuccessStatusCode) && resetResponses.All(x => x.StatusCode == HttpStatusCode.NoContent) &&
          persistedKeyJson!["auth_data"]!["api_key"]!.GetValue<string>() == persistedAppKey);
    var appKeyJson = JsonNode.Parse(VpnKeyCodec.Decode(resetFinalKey));
    var gatewayApiKey = appKeyJson!["auth_data"]!["api_key"]!.GetValue<string>();
    async Task<(string Path, bool Success)> TryConcurrentCreate(int i)
    {
        if (i % 3 == 0)
        {
            var userResponse = await parallelUser.PostAsJsonAsync("/api/devices", new { name = $"Параллельный user {i}", kind = "Android" });
            return ("user", userResponse.StatusCode == HttpStatusCode.OK);
        }
        if (i % 3 == 1)
        {
            var adminResponse = await owner.PostAsJsonAsync($"/api/admin/accounts/{parallelId}/devices", new { name = $"Параллельный admin {i}", kind = "Android" });
            return ("admin", adminResponse.StatusCode == HttpStatusCode.OK);
        }
        var requestPayload = new
        {
            os_version = "android", app_version = "test", installation_uuid = $"parallel-{i}", service_type = "amnezia-premium",
            service_protocol = "awg", public_key = Curve25519.GenerateKeyPair().PublicKey, auth_data = new { api_key = gatewayApiKey },
        };
        var gatewayPayload = await GatewayRequest(requestPayload);
        return ("gateway", gatewayPayload["http_status"] == null);
    }
    var createAttempts = await Task.WhenAll(Enumerable.Range(0, 24).Select(TryConcurrentCreate));
    Check("единый DB lock соблюдает MaxDevices в user/admin/gateway гонке", createAttempts.Count(x => x.Success) == 3 &&
          new[] { "user", "admin", "gateway" }.All(path => createAttempts.Any(x => x.Path == path && !x.Success)));
    List<Device> concurrentDevices;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        concurrentDevices = await db.Devices.Where(d => d.AccountId == Guid.Parse(parallelId)).ToListAsync();
    }
    Check("параллельные user/admin/gateway выдачи не пересекают IP", concurrentDevices.Count == 3 && concurrentDevices.Select(d => d.Ip).Distinct().Count() == 3);
    var subDeviceId = concurrentDevices[0].Id.ToString();
    var subCreated = await parallelUser.PostAsync($"/api/devices/{subDeviceId}/subscription", null);
    var subBody = await subCreated.Content.ReadFromJsonAsync<JsonNode>();
    Check("персональная v2RayTun-ссылка создаётся", subCreated.IsSuccessStatusCode && subBody!["url"]!.GetValue<string>().StartsWith("https://mayaklight.ru/sub/") && subBody["importUrl"]!.GetValue<string>() == "v2raytun://import/" + subBody["url"]!.GetValue<string>());
    Check("подписочная ссылка не кешируется", subCreated.Headers.CacheControl?.NoStore == true);
    Check("чужое устройство для подписки скрыто", (await guest.PostAsync($"/api/devices/{subDeviceId}/subscription", null)).StatusCode == HttpStatusCode.NotFound);
    var subscriptionUrl = subBody!["url"]!.GetValue<string>();
    var rotated = await parallelUser.PostAsync($"/api/devices/{subDeviceId}/subscription", null);
    var rotatedBody = await rotated.Content.ReadFromJsonAsync<JsonNode>();
    Check("перевыпуск инвалидирует предыдущую ссылку", rotated.IsSuccessStatusCode &&
          (await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery)).StatusCode == HttpStatusCode.NotFound);
    subscriptionUrl = rotatedBody!["url"]!.GetValue<string>();
    string originalClusterTitle;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var cluster = await db.Cluster.SingleAsync();
        originalClusterTitle = cluster.Title;
        cluster.Title = "Маяк VPN\r\nX-Injected: yes";
        await db.SaveChangesAsync();
    }
    var subscription = await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery);
    var subscriptionText = await subscription.Content.ReadAsStringAsync();
    var rawSubscriptionToken = new Uri(subscriptionUrl).Segments.Last();
    string clusterTitle;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var device = await db.Devices.SingleAsync(d => d.Id == Guid.Parse(subDeviceId));
        clusterTitle = await db.Cluster.Select(c => c.Title).SingleAsync();
        Check("в БД сохранён только SHA-256 подписочного токена", device.SubscriptionTokenHash == Tokens.Hash(rawSubscriptionToken) &&
              device.SubscriptionTokenHash != rawSubscriptionToken && device.SubscriptionTokenHash!.Length == 64);
        device.Enabled = false;
        await db.SaveChangesAsync();
    }
    Check("отключённое устройство не выдаёт и не обновляет подписку",
          (await parallelUser.PostAsync($"/api/devices/{subDeviceId}/subscription", null)).StatusCode == HttpStatusCode.NotFound &&
          (await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery)).StatusCode == HttpStatusCode.NotFound);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var device = await db.Devices.SingleAsync(d => d.Id == Guid.Parse(subDeviceId));
        device.Enabled = true;
        await db.SaveChangesAsync();
    }
    var expectedProfileTitle = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(clusterTitle));
    Check("GET подписки выдаёт headers и чистые VLESS строки", subscription.IsSuccessStatusCode &&
          subscription.Headers.GetValues("profile-title").Single() == "base64:" + expectedProfileTitle &&
          subscription.Headers.GetValues("profile-update-interval").Single() == "12" &&
          subscription.Headers.GetValues("profile-title").Single().StartsWith("base64:") &&
          !subscription.Headers.Contains("X-Injected") &&
          subscriptionText.Split('\n', StringSplitOptions.RemoveEmptyEntries).All(line => line.TrimEnd('\r').StartsWith("vless://")));
    Check("GET подписки не кешируется", subscription.Headers.CacheControl?.NoStore == true);
    Check("observed HTTP logs do not include the subscription bearer token", observedLogs.Count > 0 && !observedLogs.Any(line => line.Contains(rawSubscriptionToken, StringComparison.Ordinal)));
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var cluster = await db.Cluster.SingleAsync();
        cluster.Title = originalClusterTitle;
        await db.SaveChangesAsync();
    }
    string savedXrayId;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var device = await db.Devices.SingleAsync(d => d.Id == Guid.Parse(subDeviceId));
        savedXrayId = device.XrayId;
        device.XrayId = "";
        await db.SaveChangesAsync();
    }
    var noXraySubscription = await parallelUser.PostAsync($"/api/devices/{subDeviceId}/subscription", null);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var device = await db.Devices.SingleAsync(d => d.Id == Guid.Parse(subDeviceId));
        Check("пустой XrayId отклоняется без потери прежней ссылки", noXraySubscription.StatusCode == HttpStatusCode.Conflict &&
              device.SubscriptionTokenHash == Tokens.Hash(rawSubscriptionToken));
        device.XrayId = savedXrayId;
        await db.SaveChangesAsync();
    }
    var configuration = factory.Services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var configuredPublicUrl = configuration["PublicUrl"];
    configuration["PublicUrl"] = "http://vpn.example.invalid";
    var refusedSubscription = await parallelUser.PostAsync($"/api/devices/{subDeviceId}/subscription", null);
    configuration["PublicUrl"] = configuredPublicUrl;
    Check("недопустимый PublicUrl не сбрасывает прежнюю ссылку",
          refusedSubscription.StatusCode == HttpStatusCode.ServiceUnavailable && (await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery)).StatusCode == HttpStatusCode.OK);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{parallelId}", new { enabled = true, paidUntil = DateTime.UtcNow.AddDays(-1) });
    Check("просроченный аккаунт не получает VLESS конфигурацию", (await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery)).StatusCode == HttpStatusCode.NotFound);
    Check("отзыв подписки инвалидирует ссылку", (await parallelUser.DeleteAsync($"/api/devices/{subDeviceId}/subscription")).StatusCode == HttpStatusCode.NoContent &&
          (await http.GetAsync(new Uri(subscriptionUrl).PathAndQuery)).StatusCode == HttpStatusCode.NotFound);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{parallelId}", new { enabled = true, paidUntil = DateTime.UtcNow.AddDays(30) });
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        await db.Devices.Where(d => d.AccountId == Guid.Parse(parallelId)).ExecuteDeleteAsync();
    }
    var priorGatewayKeyDoc = JsonNode.Parse(VpnKeyCodec.Decode((await parallelUser.GetFromJsonAsync<JsonNode>("/api/app-key"))!["key"]!.GetValue<string>()));
    var priorGatewayKey = priorGatewayKeyDoc!["auth_data"]!["api_key"]!.GetValue<string>();
    var gatewayResetPayload = new
    {
        os_version = "android", app_version = "race", installation_uuid = "app-key-reset-race", service_type = "amnezia-premium",
        service_protocol = "awg", public_key = Curve25519.GenerateKeyPair().PublicKey, auth_data = new { api_key = priorGatewayKey },
    };
    var gatewayResetTask = GatewayRequest(gatewayResetPayload);
    var resetTask = parallelUser.PostAsync("/api/app-key/reset", null);
    await Task.WhenAll(gatewayResetTask, resetTask);
    var gatewayDuringReset = await gatewayResetTask;
    var resetResult = await resetTask;
    var activeKeyAfterReset = (await parallelUser.GetFromJsonAsync<JsonNode>("/api/app-key"))!["key"]!.GetValue<string>();
    var currentGatewayKey = JsonNode.Parse(VpnKeyCodec.Decode(activeKeyAfterReset))!["auth_data"]!["api_key"]!.GetValue<string>();
    bool resetDeviceAbsent;
    string resetKeyInDatabase;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        resetDeviceAbsent = !await db.Devices.AnyAsync(d => d.AccountId == Guid.Parse(parallelId) && d.InstallationId == "app-key-reset-race");
        resetKeyInDatabase = (await db.Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId))).AppKey!;
    }
    Check("app-key reset линеаризован с gateway config и не оставляет устройство", resetResult.StatusCode == HttpStatusCode.NoContent &&
          (gatewayDuringReset["http_status"] == null || gatewayDuringReset["http_status"]!.GetValue<int>() == 404) && resetDeviceAbsent);
    Check("lazy app-key GET не затирает ключ reset", currentGatewayKey != priorGatewayKey && resetKeyInDatabase == currentGatewayKey);
    var staleGateway = await GatewayRequest(new Dictionary<string, object?>
    {
        ["os_version"] = "android", ["app_version"] = "race", ["installation_uuid"] = "stale-after-reset",
        ["service_type"] = "amnezia-premium", ["service_protocol"] = "awg", ["public_key"] = Curve25519.GenerateKeyPair().PublicKey,
        ["auth_data"] = new { api_key = priorGatewayKey },
    });
    Check("gateway отвергает ключ, устаревший после reset", staleGateway["http_status"]?.GetValue<int>() == 404);
    var activeGateway = await GatewayRequest(new Dictionary<string, object?>
    {
        ["os_version"] = "android", ["app_version"] = "race", ["installation_uuid"] = "after-reset",
        ["service_type"] = "amnezia-premium", ["service_protocol"] = "awg", ["public_key"] = Curve25519.GenerateKeyPair().PublicKey,
        ["auth_data"] = new { api_key = currentGatewayKey },
    });
    Check("gateway принимает новый ключ после reset", activeGateway["config"] != null);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{parallelId}", new { enabled = true, paidUntil = DateTime.UtcNow.AddDays(-1) });
    var expiredAccountCode = (await (await owner.PostAsync($"/api/admin/accounts/{parallelId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>().Split("invite=")[1];
    Check("invite не выдаёт вход просроченному аккаунту", (await http.PostAsJsonAsync("/api/auth/invite", new { invite = expiredAccountCode })).StatusCode == HttpStatusCode.Forbidden);
    var expiredTelegramRequestId = Tokens.New(18);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.LoginRequests.Add(new LoginRequest { Id = expiredTelegramRequestId, InviteHash = Tokens.Hash(expiredAccountCode), ReturnPath = "/my/" });
        await db.SaveChangesAsync();
    }
    await Say(44440, "/start " + expiredTelegramRequestId, "Expired");
    bool expiredTelegramStayedUnused;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        expiredTelegramStayedUnused = (await db.Invites.SingleAsync(i => i.CodeHash == Tokens.Hash(expiredAccountCode))).UsedAt == null &&
            !(await db.Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId))).IsActive(DateTime.UtcNow);
    }
    Check("Telegram invite не реанимирует просроченный доступ и не потребляет код", expiredTelegramStayedUnused);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{parallelId}", new { enabled = false });
    var disabledCode = (await (await owner.PostAsync($"/api/admin/accounts/{parallelId}/invite", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>().Split("invite=")[1];
    Check("invite не включает отключённый аккаунт", (await http.PostAsJsonAsync("/api/auth/invite", new { invite = disabledCode })).StatusCode == HttpStatusCode.Forbidden);
    var disabledTelegramRequestId = Tokens.New(18);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.LoginRequests.Add(new LoginRequest { Id = disabledTelegramRequestId, InviteHash = Tokens.Hash(disabledCode), ReturnPath = "/my/" });
        await db.SaveChangesAsync();
    }
    await Say(44441, "/start " + disabledTelegramRequestId, "Disabled");
    bool disabledTelegramStayedUnused;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        disabledTelegramStayedUnused = (await db.Invites.SingleAsync(i => i.CodeHash == Tokens.Hash(disabledCode))).UsedAt == null &&
            !(await db.Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId))).Enabled;
    }
    Check("Telegram invite не включает отключённый аккаунт и не потребляет код", disabledTelegramStayedUnused);
    const string expiredCode = "known-expired-invite-code";
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.Invites.Add(new Invite { CodeHash = Tokens.Hash(expiredCode), AccountId = Guid.Parse(parallelId), ExpiresAt = DateTime.UtcNow.AddMinutes(-1) });
        await db.SaveChangesAsync();
    }
    Check("просроченное приглашение отклоняется", (await http.PostAsJsonAsync("/api/auth/invite", new { invite = expiredCode })).StatusCode == HttpStatusCode.Gone);

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
    Check("VLESS pool по умолчанию выключен, существующий app-key остаётся AWG",
          sub["api_config"]!["service_protocol"]!.GetValue<string>() == "awg" &&
          (await guest.GetAsync("/api/app-key?protocol=vless")).StatusCode == HttpStatusCode.NotFound);
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

    Console.WriteLine("VLESS pool: readiness, idempotence, выдача:");
    configuration["VlessPool:Enabled"] = "true";
    async Task<(Guid Id, HttpClient Client)> NewManagedPoolAccount(string name)
    {
        var account = (await (await owner.PostAsJsonAsync("/api/admin/accounts", new { name, maxDevices = 1 })).Content.ReadFromJsonAsync<JsonNode>())!;
        var accountId = account["id"]!.GetValue<Guid>();
        await owner.PatchAsJsonAsync($"/api/admin/accounts/{accountId}", new { enabled = true });
        // Auth behavior is covered above; use a fixture session instead of exhausting the unchanged 30/min login limiter.
        var fixtureToken = Tokens.New();
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        db.Sessions.Add(new Session { AccountId = accountId, TokenHash = Tokens.Hash(fixtureToken), Client = "integration fixture" });
        await db.SaveChangesAsync();
        return (accountId, As(fixtureToken));
    }
    var managedAtLimit = await NewManagedPoolAccount("managed limit integration");
    var managedAtLimitPayload = new { name = "managed limit", kind = DeviceKind.Android, protocol = "vless", installationId = "managed-limit-same-id" };
    var firstAtLimit = await managedAtLimit.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload);
    var firstAtLimitBody = (await firstAtLimit.Content.ReadFromJsonAsync<JsonNode>())!;
    var managedAtLimitId = firstAtLimitBody["device"]!["id"]!.GetValue<Guid>();
    var retriesAtLimit = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => managedAtLimit.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload)));
    var retryAtLimitBodies = await Task.WhenAll(retriesAtLimit.Select(r => r.Content.ReadFromJsonAsync<JsonNode>()));
    Check("managed same installation retries remain pending at MaxDevices including parallel requests", firstAtLimit.StatusCode == HttpStatusCode.ServiceUnavailable &&
        retriesAtLimit.All(r => r.StatusCode == HttpStatusCode.ServiceUnavailable) && retryAtLimitBodies.All(b => b?["device"]?["id"]?.GetValue<Guid>() == managedAtLimitId && b?["status"]?.GetValue<string>() == "no_ready_exit"));
    var differentAtLimit = await managedAtLimit.Client.PostAsJsonAsync("/api/devices", new { name = "new id", kind = DeviceKind.Android, protocol = "vless", installationId = "managed-limit-different-id" });
    Check("new managed installation still cannot bypass MaxDevices", differentAtLimit.StatusCode == HttpStatusCode.Conflict);
    var pendingOwnerFiles = await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files");
    var pendingAdminFiles = await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files");
    Check("pending managed owner/admin files issue no legacy key or config", pendingOwnerFiles.StatusCode == HttpStatusCode.ServiceUnavailable && pendingAdminFiles.StatusCode == HttpStatusCode.ServiceUnavailable &&
        !(await pendingOwnerFiles.Content.ReadAsStringAsync()).Contains("vpn://") && !(await pendingAdminFiles.Content.ReadAsStringAsync()).Contains("vpn://"));
    var crossAccountManaged = await NewManagedPoolAccount("managed cross account integration");
    var crossAccountResponse = await crossAccountManaged.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload);
    var crossAccountBody = (await crossAccountResponse.Content.ReadFromJsonAsync<JsonNode>())!;
    Check("managed installation lookup is scoped to current account", crossAccountResponse.StatusCode == HttpStatusCode.ServiceUnavailable &&
        crossAccountBody["device"]!["id"]!.GetValue<Guid>() != managedAtLimitId &&
        (await crossAccountManaged.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.NotFound);
    await owner.DeleteAsync($"/api/admin/accounts/{crossAccountManaged.Id}");
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        Check("parallel managed retries store one unassigned device and consume no slot", await db.Devices.CountAsync(d => d.AccountId == managedAtLimit.Id) == 1 &&
            !(await db.Devices.SingleAsync(d => d.Id == managedAtLimitId)).ExitEndpointId.HasValue);
    }
    var exitServerId = created["server"]!["id"]!.GetValue<Guid>();
    var endpointResponse = await owner.PostAsJsonAsync("/api/admin/exit-endpoints", new
    {
        serverId = exitServerId, host = "pool.example.test", port = 443, publicKey = "pool-reality-public-key",
        sni = "www.example.test", shortId = "a1b2c3d4", flow = "xtls-rprx-vision", transport = "tcp",
        capacitySlots = 1, allowNewConnections = true,
    });
    var endpointBody = await endpointResponse.Content.ReadFromJsonAsync<JsonNode>();
    Check("endpoint нового пула создаётся с явно включённым флагом", endpointResponse.StatusCode == HttpStatusCode.OK);
    var endpointId = endpointBody!["id"]!.GetValue<Guid>();
    var secondServer = await (await owner.PostAsJsonAsync("/api/admin/servers", new { name = "Второй пул тест", role = "exit", host = "second-pool.example.test" })).Content.ReadFromJsonAsync<JsonNode>();
    var secondAgent = As(secondServer!["agentToken"]!.GetValue<string>());
    var secondEndpointResponse = await owner.PostAsJsonAsync("/api/admin/exit-endpoints", new
    {
        serverId = secondServer["server"]!["id"]!.GetValue<Guid>(), host = "second-pool.example.test", port = 443,
        publicKey = "second-pool-key", sni = "www.example.test", shortId = "abcd", flow = "xtls-rprx-vision",
        transport = "tcp", capacitySlots = 1, allowNewConnections = false,
    });
    var secondEndpointBody = await secondEndpointResponse.Content.ReadFromJsonAsync<JsonNode>();
    var secondEndpointId = secondEndpointBody!["id"]!.GetValue<Guid>();
    var secondBootstrapState = await secondAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("authenticated agent receives its own endpoint identity while pool is empty", secondBootstrapState?.PoolEndpoint?.EndpointId == secondEndpointId &&
          secondBootstrapState.PoolEndpoint.IdentityVersion == 1 && secondBootstrapState.PoolEndpoint.DesiredCredentialsRevision == 0 &&
          secondBootstrapState.PoolDevices.Count == 0 && secondBootstrapState.PoolEndpoint.Host == "second-pool.example.test");
    await secondAgent.PostAsJsonAsync(AgentPaths.Report, PoolReport(secondBootstrapState!.PoolEndpoint!), json);
    bool isolatedReports;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        isolatedReports = (await db.ExitEndpoints.SingleAsync(e => e.Id == endpointId)).ProtocolReportReceivedAt == null &&
            (await db.ExitEndpoints.SingleAsync(e => e.Id == secondEndpointId)).ProtocolReportReceivedAt != null;
    }
    Check("VLESS report другого authenticated agent не меняет readiness первого endpoint", secondEndpointResponse.StatusCode == HttpStatusCode.OK && isolatedReports);
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{secondEndpointId}", new { sni = "changed-mask.example.test" });
    var changedIdentityState = await secondAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    bool identityReset;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var e = await db.ExitEndpoints.SingleAsync(x => x.Id == secondEndpointId);
        identityReset = e.ProtocolReportReceivedAt == null && !ClusterService.IsPoolReady(e, DateTime.UtcNow);
    }
    Check("изменение публичной identity увеличивает state version и сбрасывает readiness", identityReset &&
          changedIdentityState?.PoolEndpoint?.IdentityVersion == 2 && changedIdentityState.PoolEndpoint.Sni == "changed-mask.example.test");
    await secondAgent.PostAsJsonAsync(AgentPaths.Report, PoolReport(secondBootstrapState!.PoolEndpoint!), json);
    bool staleIdentityRejected;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        staleIdentityRejected = !ClusterService.IsPoolReady(await db.ExitEndpoints.SingleAsync(x => x.Id == secondEndpointId), DateTime.UtcNow);
    }
    Check("отчёт от прежней identity version не восстанавливает readiness", staleIdentityRejected);
    var vlessRoot = JsonNode.Parse(VpnKeyCodec.Decode((await guest.GetFromJsonAsync<JsonNode>("/api/app-key?protocol=vless"))!["key"]!.GetValue<string>()))!;
    Check("только явный запрос выдаёт VLESS subscription root", vlessRoot["api_config"]!["service_protocol"]!.GetValue<string>() == "vless");
    var poolPayload = new Dictionary<string, object?>
    {
        ["os_version"] = "android", ["app_version"] = "pool-test", ["installation_uuid"] = "pool-install-1",
        ["service_type"] = "amnezia-premium", ["service_protocol"] = "vless",
        ["auth_data"] = new { api_key = apiKey },
    };
    var notReady = await GatewayRequest(poolPayload);
    Check("без VLESS protocol ACK gateway возвращает no_ready_exit", notReady["http_status"]?.GetValue<int>() == 503 && notReady["message"]?.GetValue<string>() == "no_ready_exit");
    var bootstrapState = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("первый AgentState содержит endpoint identity/version до назначения credentials", bootstrapState?.PoolEndpoint?.EndpointId == endpointId &&
          bootstrapState.PoolEndpoint.IdentityVersion == 1 && bootstrapState.PoolEndpoint.DesiredCredentialsRevision == 0 && bootstrapState.PoolDevices.Count == 0 &&
          bootstrapState.PoolEndpoint.PublicKey == "pool-reality-public-key");
    await agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(bootstrapState!.PoolEndpoint!), json);
    var pendingConfig = await GatewayRequest(poolPayload);
    Check("новое назначение остаётся provisioning до credentials ACK", pendingConfig["message"]?.GetValue<string>() == "provisioning");
    Guid poolDeviceId;
    string firstPoolXrayId;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var d = await db.Devices.SingleAsync(x => x.InstallationId == "pool-install-1");
        poolDeviceId = d.Id; firstPoolXrayId = d.XrayId;
        Check("назначение стабильно и занимает один административный слот", d.ServiceProtocol == "vless" && d.ExitEndpointId == endpointId && d.CredentialsRevision == 1 &&
              (await db.ExitEndpoints.SingleAsync(e => e.Id == endpointId)).OccupiedSlots == 1);
    }
    var assignedState = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("AgentState после назначения содержит incremented revision и assigned credential", assignedState?.PoolEndpoint?.DesiredCredentialsRevision == 1 &&
          assignedState.PoolDevices.Any(d => d.DeviceId == poolDeviceId && d.CredentialsRevision == 1 && d.XrayId == firstPoolXrayId));
    await agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(assignedState!.PoolEndpoint!), json);
    var readyConfig = await GatewayRequest(poolPayload);
    var readyRoot = readyConfig["config"]?.GetValue<string>() is string encoded ? JsonNode.Parse(VpnKeyCodec.Decode(encoded)) : null;
    Check("после protocol ACK gateway выдаёт только amnezia-xray VLESS root", readyRoot?["api_config"]?["service_protocol"]?.GetValue<string>() == "vless" &&
          readyRoot?["defaultContainer"]?.GetValue<string>() == "amnezia-xray" && readyRoot?["containers"]?.AsArray().Count == 1 &&
          readyRoot["containers"]![0]!["container"]?.GetValue<string>() == "amnezia-xray");
    long poolRevisionBeforeRetry;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        poolRevisionBeforeRetry = await db.Cluster.Select(c => c.Revision).SingleAsync();
    }
    var repeatedPoolConfigs = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => GatewayRequest(poolPayload)));
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var d = await db.Devices.SingleAsync(x => x.InstallationId == "pool-install-1");
        var revision = await db.Cluster.Select(c => c.Revision).SingleAsync();
        Check("повторные gateway запросы сохраняют XrayId и не bump-ят revision", d.Id == poolDeviceId && d.XrayId == firstPoolXrayId && revision == poolRevisionBeforeRetry &&
              repeatedPoolConfigs.All(x => x["config"] != null));
    }
    var poolState = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("pool credentials отделены от legacy desired state", poolState!.PoolDevices.Any(d => d.DeviceId == poolDeviceId && d.XrayId == firstPoolXrayId) &&
          poolState.Accounts.SelectMany(a => a.Devices).All(d => d.Id != poolDeviceId));
    var poolSubscription = await guest.PostAsync($"/api/devices/{poolDeviceId}/subscription", null);
    var poolSubscriptionBody = await poolSubscription.Content.ReadFromJsonAsync<JsonNode>();
    var poolSubscriptionUrl = poolSubscriptionBody!["url"]!.GetValue<string>();
    var poolSubscriptionLink = (await http.GetStringAsync(new Uri(poolSubscriptionUrl).PathAndQuery)).Trim();
    Check("/sub использует ту же закреплённую identity и host", poolSubscriptionLink.StartsWith($"vless://{firstPoolXrayId}@pool.example.test:443?", StringComparison.Ordinal));
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { maxDevices = 8 });
    var noCapacity = await GatewayRequest(new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "pool-install-2" });
    Check("capacity не переполняется и возвращает no_ready_exit", noCapacity["message"]?.GetValue<string>() == "no_ready_exit");
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var count = await db.Devices.CountAsync(x => x.InstallationId == "pool-install-2");
        Check("повтор без capacity остаётся идемпотентным по installation", count == 1);
    }
    var managedPoolPayload = new { name = "Managed pool", kind = DeviceKind.Android, protocol = "vless", installationId = "managed-install-1" };
    var managedPoolFirst = await guest.PostAsJsonAsync("/api/devices", managedPoolPayload);
    var managedPoolFirstBody = await managedPoolFirst.Content.ReadFromJsonAsync<JsonNode>();
    var managedPoolRetry = await guest.PostAsJsonAsync("/api/devices", managedPoolPayload);
    var managedPoolRetryBody = await managedPoolRetry.Content.ReadFromJsonAsync<JsonNode>();
    Check("managed VLESS create без места остаётся provisioning/no_ready_exit и retry не дублирует device",
          managedPoolFirst.StatusCode == HttpStatusCode.ServiceUnavailable && managedPoolRetry.StatusCode == HttpStatusCode.ServiceUnavailable &&
          managedPoolFirstBody?["device"]?["id"]?.GetValue<string>() == managedPoolRetryBody?["device"]?["id"]?.GetValue<string>());
    await guest.DeleteAsync($"/api/devices/{poolDeviceId}");
    var emptyAfterRemoval = await agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    Check("после удаления последнего pool device endpoint state сохраняется, список пуст и desired revision растёт", emptyAfterRemoval?.PoolEndpoint?.EndpointId == endpointId &&
          emptyAfterRemoval.PoolEndpoint.IdentityVersion == 1 && emptyAfterRemoval.PoolEndpoint.DesiredCredentialsRevision == 2 && emptyAfterRemoval.PoolDevices.Count == 0);
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{secondEndpointId}", new { allowNewConnections = true });
    var secondReadyState = await secondAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
    await secondAgent.PostAsJsonAsync(AgentPaths.Report, PoolReport(secondReadyState!.PoolEndpoint!), json);
    var racePayloadA = new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "pool-race-a" };
    var racePayloadB = new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "pool-race-b" };
    var raceResults = await Task.WhenAll(GatewayRequest(racePayloadA), GatewayRequest(racePayloadB));
    var raceMessages = raceResults.Select(x => x["message"]?.GetValue<string>()).ToList();
    bool capacityStayedAtomic;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var assigned = await db.Devices.CountAsync(d => (d.InstallationId == "pool-race-a" || d.InstallationId == "pool-race-b") && d.ExitEndpointId == secondEndpointId);
        var slots = (await db.ExitEndpoints.SingleAsync(e => e.Id == secondEndpointId)).OccupiedSlots;
        capacityStayedAtomic = assigned == 1 && slots == 1;
    }
    Check("конкурентные разные установки не переполняют один slot", capacityStayedAtomic && raceMessages.Count(m => m == "provisioning") == 1 && raceMessages.Count(m => m == "no_ready_exit") == 1);

    Console.WriteLine("Pool ACK binding: access mutations and natural expiry:");
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { maxDevices = 16, clearPaidUntil = true });
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{parallelId}", new { enabled = true, clearPaidUntil = true, maxDevices = 16 });
    await parallelUser.GetAsync("/api/app-key");
    string otherPoolKey;
    await using (var scope = factory.Services.CreateAsyncScope())
        otherPoolKey = (await scope.ServiceProvider.GetRequiredService<MayakDb>().Accounts.SingleAsync(a => a.Id == Guid.Parse(parallelId))).AppKey!;
    async Task<(Guid Id, HttpClient Agent)> NewAckEndpoint(string host, int slots, bool allow)
    {
        var node = await (await owner.PostAsJsonAsync("/api/admin/servers", new { name = host, role = "exit", host })).Content.ReadFromJsonAsync<JsonNode>();
        var endpoint = await (await owner.PostAsJsonAsync("/api/admin/exit-endpoints", new
        {
            serverId = node!["server"]!["id"]!.GetValue<Guid>(), host, port = 443, publicKey = "ack-key-" + host,
            sni = "mask.example.test", shortId = "abcd", transport = "tcp", capacitySlots = slots, allowNewConnections = allow,
        })).Content.ReadFromJsonAsync<JsonNode>();
        var nodeAgent = As(node!["agentToken"]!.GetValue<string>());
        var initial = await nodeAgent.GetFromJsonAsync<AgentState>(AgentPaths.State, json);
        await nodeAgent.PostAsJsonAsync(AgentPaths.Report, PoolReport(initial!.PoolEndpoint!), json);
        return (endpoint!["id"]!.GetValue<Guid>(), nodeAgent);
    }
    var sharedAck = await NewAckEndpoint("ack-shared.example.test", 4, true);
    var isolatedAck = await NewAckEndpoint("ack-isolated.example.test", 2, false);
    var ackPayloadA = new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "ack-account-a" };
    var ackPayloadB = new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "ack-account-b", ["auth_data"] = new { api_key = otherPoolKey } };
    await GatewayRequest(ackPayloadA);
    var ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    await GatewayRequest(ackPayloadB);
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    Guid ackDeviceA, ackDeviceB;
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        ackDeviceA = (await db.Devices.SingleAsync(d => d.InstallationId == "ack-account-a")).Id;
        ackDeviceB = (await db.Devices.SingleAsync(d => d.InstallationId == "ack-account-b")).Id;
    }
    var ackXrayA = ackState.PoolDevices.Single(d => d.DeviceId == ackDeviceA).XrayId;
    var ackUrlA = (await (await guest.PostAsync($"/api/devices/{ackDeviceA}/subscription", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>();
    var ackUrlB = (await (await parallelUser.PostAsync($"/api/devices/{ackDeviceB}/subscription", null)).Content.ReadFromJsonAsync<JsonNode>())!["url"]!.GetValue<string>();
    var ackPathA = new Uri(ackUrlA).PathAndQuery;
    var ackPathB = new Uri(ackUrlB).PathAndQuery;
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{sharedAck.Id}", new { allowNewConnections = false });
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{isolatedAck.Id}", new { allowNewConnections = true });
    var isolatedPayload = new Dictionary<string, object?>(ackPayloadB) { ["installation_uuid"] = "ack-isolated-b" };
    await GatewayRequest(isolatedPayload);
    var isolatedState = (await isolatedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await isolatedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(isolatedState.PoolEndpoint!), json);
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{sharedAck.Id}", new { allowNewConnections = true });
    async Task<(long Revision, long Global, int Slots, bool Ready)> AckSnapshot(Guid endpoint)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        var e = await db.ExitEndpoints.SingleAsync(e => e.Id == endpoint);
        return (e.AppliedCredentialsRevision, await db.Cluster.Select(c => c.Revision).SingleAsync(), e.OccupiedSlots, ClusterService.IsPoolReady(e, DateTime.UtcNow));
    }
    async Task CheckPendingAck(string criterion, AgentPoolEndpoint oldAck, long minimumRevision)
    {
        await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(oldAck), json);
        var snapshot = await AckSnapshot(sharedAck.Id);
        var config = await GatewayRequest(ackPayloadB);
        var sub = await http.GetAsync(ackPathB);
        var issue = await parallelUser.PostAsync($"/api/devices/{ackDeviceB}/subscription", null);
        Check(criterion, snapshot.Revision >= minimumRevision && !snapshot.Ready && snapshot.Slots == 2 &&
            config["message"]?.GetValue<string>() == "provisioning" && sub.StatusCode == HttpStatusCode.NotFound && issue.StatusCode == HttpStatusCode.ServiceUnavailable);
    }
    var initialAckRevision = ackState.PoolEndpoint!.DesiredCredentialsRevision;
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { enabled = false });
    await CheckPendingAck("disable invalidates old ACK and withholds other user's shared-endpoint config/subscription", ackState.PoolEndpoint, initialAckRevision + 1);
    var disabledAckState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    Check("disabled account is absent from desired membership while other user remains", disabledAckState.PoolDevices.All(d => d.DeviceId != ackDeviceA) && disabledAckState.PoolDevices.Any(d => d.DeviceId == ackDeviceB));
    Check("disabled account gateway and existing subscription are denied", (await GatewayRequest(ackPayloadA))["http_status"]?.GetValue<int>() == 402 &&
        (await http.GetAsync(ackPathA)).StatusCode == HttpStatusCode.NotFound);
    var stableBefore = await AckSnapshot(sharedAck.Id);
    for (var poll = 0; poll < 3; poll++)
    {
        await sharedAck.Agent.GetAsync(AgentPaths.State);
        await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint), json);
        await GatewayRequest(ackPayloadB);
        await http.GetAsync(ackPathB);
    }
    var stableAfter = await AckSnapshot(sharedAck.Id);
    Check("repeated state/report/config/sub polls do not bump revisions or consume slots", stableAfter == stableBefore);
    var isolatedAfterDisable = await AckSnapshot(isolatedAck.Id);
    Check("account mutation leaves unrelated endpoint revision/ACK/config intact", isolatedAfterDisable.Revision == isolatedState.PoolEndpoint!.DesiredCredentialsRevision &&
        isolatedAfterDisable.Ready && (await GatewayRequest(isolatedPayload))["config"] != null);
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(disabledAckState.PoolEndpoint!), json);
    Check("fresh removal ACK restores shared endpoint only for still-active user", (await GatewayRequest(ackPayloadB))["config"] != null &&
        (await http.GetAsync(ackPathB)).StatusCode == HttpStatusCode.OK && (await GatewayRequest(ackPayloadA))["config"] == null);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { enabled = true });
    await CheckPendingAck("re-enable requires new ACK rather than reusing removal ACK", disabledAckState.PoolEndpoint!, disabledAckState.PoolEndpoint!.DesiredCredentialsRevision + 1);
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    Check("fresh re-enable ACK restores same device XrayId and subscription", ackState.PoolDevices.Single(d => d.DeviceId == ackDeviceA).XrayId == ackXrayA &&
        (await GatewayRequest(ackPayloadA))["config"] != null && (await http.GetAsync(ackPathA)).StatusCode == HttpStatusCode.OK);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { paidUntil = DateTime.UtcNow.AddDays(-1) });
    await CheckPendingAck("PaidUntil past PATCH invalidates previously ready ACK", ackState.PoolEndpoint!, ackState.PoolEndpoint!.DesiredCredentialsRevision + 1);
    var expiredAckState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(expiredAckState.PoolEndpoint!), json);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { clearPaidUntil = true });
    await CheckPendingAck("renewal requires ACK for restored effective membership", expiredAckState.PoolEndpoint!, expiredAckState.PoolEndpoint!.DesiredCredentialsRevision + 1);
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    var expiresAt = DateTime.UtcNow.AddSeconds(2);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { paidUntil = expiresAt });
    Check("future expiry date alone does not alter effective membership revision", (await AckSnapshot(sharedAck.Id)).Revision == ackState.PoolEndpoint!.DesiredCredentialsRevision);
    await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, (expiresAt - DateTime.UtcNow).TotalMilliseconds + 80)));
    await CheckPendingAck("natural clock expiry reconciles before report and rejects pre-expiry ACK", ackState.PoolEndpoint!, ackState.PoolEndpoint!.DesiredCredentialsRevision + 1);
    var naturalExpired = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    Check("natural expiry changes desired list without an API write and retains occupied slots", naturalExpired.PoolDevices.All(d => d.DeviceId != ackDeviceA) && (await AckSnapshot(sharedAck.Id)).Slots == 2);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { clearPaidUntil = true });
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    expiresAt = DateTime.UtcNow.AddSeconds(2);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { paidUntil = expiresAt });
    await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, (expiresAt - DateTime.UtcNow).TotalMilliseconds + 80)));
    // No state, report or grant observation between expiry and renewal: pre/post mutation reconciliation is essential.
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { clearPaidUntil = true });
    await CheckPendingAck("unobserved expiry then renewal cannot reuse old active-membership ACK", ackState.PoolEndpoint!, ackState.PoolEndpoint!.DesiredCredentialsRevision + 2);
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    var futureAck = PoolReport(ackState.PoolEndpoint!); futureAck.CredentialsRevision += 50;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, futureAck, json);
    Check("future report revision does not authorize current desired state", !(await AckSnapshot(sharedAck.Id)).Ready);
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    Check("fresh exact ACK restores access after renewal without reallocating", (await GatewayRequest(ackPayloadA))["config"] != null &&
        (await http.GetAsync(ackPathA)).StatusCode == HttpStatusCode.OK && (await AckSnapshot(sharedAck.Id)).Slots == 2);
    foreach (var firstObserver in new[] { "state", "gateway", "subscription" })
    {
        expiresAt = DateTime.UtcNow.AddSeconds(2);
        await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { paidUntil = expiresAt });
        var beforeExpiry = await AckSnapshot(sharedAck.Id);
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, (expiresAt - DateTime.UtcNow).TotalMilliseconds + 80)));
        var deliveryWithheld = true;
        if (firstObserver == "state")
            await sharedAck.Agent.GetAsync(AgentPaths.State);
        else if (firstObserver == "gateway")
            deliveryWithheld = (await GatewayRequest(ackPayloadB))["message"]?.GetValue<string>() == "provisioning";
        else
            deliveryWithheld = (await http.GetAsync(ackPathB)).StatusCode == HttpStatusCode.NotFound;
        var afterExpiry = await AckSnapshot(sharedAck.Id);
        Check($"natural expiry reconciles when first observed by {firstObserver}", beforeExpiry.Ready && !afterExpiry.Ready &&
            afterExpiry.Revision == beforeExpiry.Revision + 1 && afterExpiry.Slots == beforeExpiry.Slots && deliveryWithheld);
        await owner.PatchAsJsonAsync($"/api/admin/accounts/{guestAcc["id"]}", new { clearPaidUntil = true });
        ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
        await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    }
    await owner.PatchAsJsonAsync($"/api/admin/devices/{ackDeviceB}", new { enabled = false });
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);
    var disabledDeviceState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    Check("device disable changes effective credential payload and invalidates shared ACK", disabledDeviceState.PoolDevices.Single(d => d.DeviceId == ackDeviceB).Enabled == false &&
        !(await AckSnapshot(sharedAck.Id)).Ready && (await GatewayRequest(ackPayloadA))["message"]?.GetValue<string>() == "provisioning" &&
        (await http.GetAsync(ackPathB)).StatusCode == HttpStatusCode.NotFound);
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(disabledDeviceState.PoolEndpoint!), json);
    await owner.PatchAsJsonAsync($"/api/admin/devices/{ackDeviceB}", new { enabled = true });
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(disabledDeviceState.PoolEndpoint!), json);
    Check("device re-enable requires fresh ACK and retains occupied allocation", !(await AckSnapshot(sharedAck.Id)).Ready &&
        (await AckSnapshot(sharedAck.Id)).Slots == 2 && (await GatewayRequest(ackPayloadB))["message"]?.GetValue<string>() == "provisioning");
    ackState = (await sharedAck.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await sharedAck.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(ackState.PoolEndpoint!), json);

    Console.WriteLine("Managed file delivery and native consumer fixtures:");
    var deliveryEndpoint = await NewAckEndpoint("selected-delivery.example.test", 2, true);
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{deliveryEndpoint.Id}", new { flow = "xtls-rprx-vision", fingerprint = "firefox" });
    var deliveryState = (await deliveryEndpoint.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    var assignedAtLimit = await managedAtLimit.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload);
    var assignedAtLimitBody = (await assignedAtLimit.Content.ReadFromJsonAsync<JsonNode>())!;
    Check("managed at-limit retry assigns existing device but withholds files until assignment ACK", assignedAtLimit.StatusCode == HttpStatusCode.ServiceUnavailable &&
        assignedAtLimitBody["device"]!["id"]!.GetValue<Guid>() == managedAtLimitId && assignedAtLimitBody["status"]!.GetValue<string>() == "provisioning" && assignedAtLimitBody["files"] == null);
    Check("unACKed assignment owner/admin exports return retryable no-config errors", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable);
    deliveryState = (await deliveryEndpoint.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    var readyAtLimit = await managedAtLimit.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload);
    var readyAtLimitBody = (await readyAtLimit.Content.ReadFromJsonAsync<JsonNode>())!;
    var ownerPoolFiles = (await managedAtLimit.Client.GetFromJsonAsync<JsonNode>($"/api/devices/{managedAtLimitId}/files"))!;
    var adminPoolFiles = (await owner.GetFromJsonAsync<JsonNode>($"/api/admin/devices/{managedAtLimitId}/files"))!;
    var ownerPoolRoot = JsonNode.Parse(VpnKeyCodec.Decode(ownerPoolFiles["vpnKey"]!.GetValue<string>()))!;
    var adminPoolRoot = JsonNode.Parse(VpnKeyCodec.Decode(adminPoolFiles["vpnKey"]!.GetValue<string>()))!;
    var poolNativeJson = JsonNode.Parse(ownerPoolFiles["conf"]!.GetValue<string>())!;
    Check("ready managed owner/admin exports use selected Xray identity only and ready retry keeps device", readyAtLimit.IsSuccessStatusCode &&
        readyAtLimitBody["device"]!["id"]!.GetValue<Guid>() == managedAtLimitId && ownerPoolRoot["hostName"]!.GetValue<string>() == "selected-delivery.example.test" &&
        adminPoolRoot["hostName"]!.GetValue<string>() == "selected-delivery.example.test" && ownerPoolFiles["confName"]!.GetValue<string>().EndsWith(".json") &&
        poolNativeJson["outbounds"]![0]!["protocol"]!.GetValue<string>() == "vless" && !ownerPoolFiles["conf"]!.GetValue<string>().Contains("[Interface]"));
    await CaptureNativeFixture("owner-files-tcp", ownerPoolRoot, deliveryEndpoint.Id, managedAtLimitId, ownerPoolFiles["conf"]!.GetValue<string>());
    await CaptureNativeFixture("admin-files-tcp", adminPoolRoot, deliveryEndpoint.Id, managedAtLimitId, adminPoolFiles["conf"]!.GetValue<string>());
    await managedAtLimit.Client.GetAsync("/api/app-key?protocol=vless");
    string managedDeliveryKey;
    await using (var scope = factory.Services.CreateAsyncScope())
        managedDeliveryKey = (await scope.ServiceProvider.GetRequiredService<MayakDb>().Accounts.SingleAsync(a => a.Id == managedAtLimit.Id)).AppKey!;
    var managedGatewayPayload = new Dictionary<string, object?>(poolPayload) { ["installation_uuid"] = "managed-limit-same-id", ["auth_data"] = new { api_key = managedDeliveryKey } };
    var managedGatewayTcp = await GatewayRequest(managedGatewayPayload);
    var poolAsAwg = await GatewayRequest(new Dictionary<string, object?>(managedGatewayPayload) { ["service_protocol"] = "awg", ["public_key"] = Curve25519.GenerateKeyPair().PublicKey });
    Check("managed pool gateway cannot bypass protocol readiness through AWG request", poolAsAwg["http_status"]?.GetValue<int>() == 409);
    await CaptureNativeFixture("gateway-tcp", JsonNode.Parse(VpnKeyCodec.Decode(managedGatewayTcp["config"]!.GetValue<string>()))!, deliveryEndpoint.Id, managedAtLimitId);
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!, false), json);
    Check("negative runtime report withholds managed owner/admin exports", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable);
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
        (await db.ExitEndpoints.SingleAsync(e => e.Id == deliveryEndpoint.Id)).ProtocolReportReceivedAt = DateTime.UtcNow.AddSeconds(-121);
        await db.SaveChangesAsync();
    }
    Check("stale ACK withholds managed owner/admin exports", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable);
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{managedAtLimit.Id}", new { enabled = false });
    Check("disabled managed account denied on owner and admin export routes", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.Forbidden &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.Forbidden);
    await owner.PatchAsJsonAsync($"/api/admin/accounts/{managedAtLimit.Id}", new { enabled = true });
    deliveryState = (await deliveryEndpoint.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    await owner.PatchAsJsonAsync($"/api/admin/exit-endpoints/{deliveryEndpoint.Id}", new { transport = "xhttp", flow = "", xhttpPath = "/selected/path", xhttpHost = "selected-front.example.test", xhttpMode = "stream-up" });
    Check("changed selected identity withholds managed owner/admin exports until new identity ACK", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.ServiceUnavailable);
    deliveryState = (await deliveryEndpoint.Agent.GetFromJsonAsync<AgentState>(AgentPaths.State, json))!;
    await deliveryEndpoint.Agent.PostAsJsonAsync(AgentPaths.Report, PoolReport(deliveryState.PoolEndpoint!), json);
    var ownerXhttpFiles = (await managedAtLimit.Client.GetFromJsonAsync<JsonNode>($"/api/devices/{managedAtLimitId}/files"))!;
    var adminXhttpFiles = (await owner.GetFromJsonAsync<JsonNode>($"/api/admin/devices/{managedAtLimitId}/files"))!;
    await CaptureNativeFixture("owner-files-xhttp", JsonNode.Parse(VpnKeyCodec.Decode(ownerXhttpFiles["vpnKey"]!.GetValue<string>()))!, deliveryEndpoint.Id, managedAtLimitId, ownerXhttpFiles["conf"]!.GetValue<string>());
    await CaptureNativeFixture("admin-files-xhttp", JsonNode.Parse(VpnKeyCodec.Decode(adminXhttpFiles["vpnKey"]!.GetValue<string>()))!, deliveryEndpoint.Id, managedAtLimitId, adminXhttpFiles["conf"]!.GetValue<string>());
    var managedGatewayXhttp = await GatewayRequest(managedGatewayPayload);
    await CaptureNativeFixture("gateway-xhttp", JsonNode.Parse(VpnKeyCodec.Decode(managedGatewayXhttp["config"]!.GetValue<string>()))!, deliveryEndpoint.Id, managedAtLimitId);
    Check("ready at-limit repeated creates keep one occupied assignment after identity change", (await managedAtLimit.Client.PostAsJsonAsync("/api/devices", managedAtLimitPayload)).IsSuccessStatusCode &&
        (await AckSnapshot(deliveryEndpoint.Id)).Slots == 1);
    await owner.PatchAsJsonAsync($"/api/admin/devices/{managedAtLimitId}", new { enabled = false });
    Check("disabled managed device denied on owner/admin export routes", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.Forbidden &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.Forbidden);
    await managedAtLimit.Client.DeleteAsync($"/api/devices/{managedAtLimitId}");
    Check("revoked managed device absent from owner/admin export routes", (await managedAtLimit.Client.GetAsync($"/api/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.NotFound &&
        (await owner.GetAsync($"/api/admin/devices/{managedAtLimitId}/files")).StatusCode == HttpStatusCode.NotFound);

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
    Check("после потери freshness сервер остаётся quarantined и не переключает активный выход", (await owner.PatchAsJsonAsync($"/api/admin/servers/{provisionId}", new { active = true })).StatusCode == HttpStatusCode.Conflict);
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

sealed class ProvisioningProbeShell : Mayak.Core.Server.IShell
{
    public string Sudo => IsRoot ? "" : "sudo -n ";
    public bool IsRoot { get; init; } = true;
    public bool SudoWorks { get; init; } = true;
    public string? ServerFingerprint => null;
    public string? JumpFingerprint => null;
    public string SocketOutput { get; init; } = "";
    public string ArtifactOutput { get; init; } = "";
    public string UnitOutput { get; init; } = "";
    public string LinkOutput { get; init; } = "1: lo: <LOOPBACK> mtu 65536 state UNKNOWN\n2: eth0: <BROADCAST> mtu 1500 state UP";
    public string WireGuardOutput { get; init; } = "__NO_WG_TOOL__";
    public string ContainerOutput { get; init; } = "__ABSENT_docker__\n__ABSENT_podman__";
    public Func<string, CommandResult>? ContainerCommandRunner { get; init; }
    public HashSet<string> FailFragments { get; } = new(StringComparer.Ordinal);
    public void Connect() => throw new NotSupportedException();
    public bool IsAlive() => false;
    public void Dispose() { }
    public string UploadTemp(string content, string suffix = "") => throw new NotSupportedException();
    public void WriteHostFile(string content, string remotePath, string mode = "644") => throw new NotSupportedException();
    public string RunChecked(string command, string what, TimeSpan? timeout = null) => throw new NotSupportedException();
    public CommandResult RunScript(string script, TimeSpan timeout) => throw new NotSupportedException();
    public CommandResult Run(string command, TimeSpan? timeout = null)
    {
        if (FailFragments.Any(command.Contains)) return new CommandResult(1, "", "Permission denied");
        if (command == "cat /etc/os-release") return new CommandResult(0, "ID=ubuntu\nVERSION_ID=\"24.04\"", "");
        if (command == "uname -m") return new CommandResult(0, "x86_64", "");
        if (command == "sudo -n true") return new CommandResult(SudoWorks ? 0 : 1, "", SudoWorks ? "" : "denied");
        if (command.Contains("ss -H -lntu", StringComparison.Ordinal)) return new CommandResult(0, SocketOutput, "");
        if (command.Contains("for r in docker podman", StringComparison.Ordinal)) return ContainerCommandRunner?.Invoke(command) ?? new CommandResult(0, ContainerOutput, "");
        if (command.Contains("/etc/mayak/agent.json", StringComparison.Ordinal)) return new CommandResult(0, ArtifactOutput, "");
        if (command.Contains("systemctl list-units", StringComparison.Ordinal)) return new CommandResult(0, UnitOutput, "");
        if (command == "ip -o link show") return new CommandResult(0, LinkOutput, "");
        if (command.Contains("command -v wg", StringComparison.Ordinal)) return new CommandResult(0, WireGuardOutput, "");
        throw new InvalidOperationException($"Unexpected preflight command: {command}");
    }
}

sealed class RecordingProvisioningShell : Mayak.Core.Server.IShell
{
    public string Sudo { get; init; } = "";
    public bool IsRoot { get; init; } = true;
    public string? ServerFingerprint => null;
    public string? JumpFingerprint => null;
    public List<string> Commands { get; } = new();
    public List<(string Content, string Path, string Mode)> Files { get; } = new();
    public void Connect() => throw new NotSupportedException();
    public bool IsAlive() => false;
    public void Dispose() { }
    public string UploadTemp(string content, string suffix = "") => throw new NotSupportedException();
    public CommandResult Run(string command, TimeSpan? timeout = null) { Commands.Add(command); return new CommandResult(0, "", ""); }
    public string RunChecked(string command, string what, TimeSpan? timeout = null) { Commands.Add(command); return ""; }
    public void WriteHostFile(string content, string remotePath, string mode = "644") => Files.Add((content, remotePath, mode));
    public CommandResult RunScript(string script, TimeSpan timeout) => new(0, "", "");
}

sealed class FakeProvisioningBackend : IProvisioningBackend
{
    public const string Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    public Func<ProvisioningInstallContext, Func<string, Task>, CancellationToken, Task>? Install { get; set; }
    public Func<Task>? BeforeInspect { get; set; }

    public Task<string> ReadHostFingerprintAsync(string host, int port, CancellationToken ct) => Task.FromResult(Fingerprint);

    public async Task<ProvisioningInspection> InspectAsync(ProvisioningCredentials credentials, ProvisioningPlan plan, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (credentials.TrustedFingerprint != Fingerprint) throw new ProvisioningException("SSH fingerprint mismatch");
        if (BeforeInspect != null) await BeforeInspect();
        return new ProvisioningInspection(true, null, "ubuntu", "24.04", "x86_64", true, plan.AwgPort, plan.XrayPort, plan.BootstrapIdentity);
    }

    public Task InstallAsync(ProvisioningInstallContext context, Func<string, Task> progress, CancellationToken ct) =>
        Install?.Invoke(context, progress, ct) ?? Task.FromException(new InvalidOperationException("Test install callback is missing"));
}

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

sealed class CaptureLoggerProvider(ConcurrentQueue<string> entries) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new CaptureLogger(categoryName, entries);
    public void Dispose() { }

    private sealed class CaptureLogger(string category, ConcurrentQueue<string> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            entries.Enqueue($"{category}: {formatter(state, exception)}");
    }
}
