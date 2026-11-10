using System.Text.Json;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Api.Services;
using Mayak.Core.Agent;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;
using Npgsql;

if (args.Length != 1) throw new ArgumentException("Pass an isolated PostgreSQL server connection string without Database.");
var adminCs = new NpgsqlConnectionStringBuilder(args[0]) { Database = "postgres" }.ConnectionString;
var name = "mayak_admission_" + Guid.NewGuid().ToString("N")[..10];
await using (var admin = new NpgsqlConnection(adminCs))
{
    await admin.OpenAsync();
    await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", admin);
    await cmd.ExecuteNonQueryAsync();
}
var cs = new NpgsqlConnectionStringBuilder(args[0]) { Database = name }.ConnectionString;
var opts = new DbContextOptionsBuilder<MayakDb>().UseNpgsql(cs).Options;
var failed = 0;
void Check(string label, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {label}"); if (!ok) failed++; }

try
{
    await using (var db = new MayakDb(opts)) await db.Database.MigrateAsync();
    var account1 = new Account { Name = "managed-a", AppKey = "a" };
    var account2 = new Account { Name = "managed-b", AppKey = "b" };
    var device1 = DeviceFor(account1, true, "10.8.1.2");
    var device2 = DeviceFor(account2, true, "10.8.1.3");
    var cluster = new ClusterIdentity { Id = 1, Revision = 7, AwgJson = JsonSerializer.Serialize(new ServerEndpoint { Host = "81.29.149.103", Port = 51820 }) };
    var server = ReadyServer(cluster, 1);
    await using (var db = new MayakDb(opts))
    {
        db.Accounts.AddRange(account1, account2);
        db.Devices.AddRange(device1, device2);
        db.Cluster.Add(cluster);
        db.Servers.Add(server);
        await db.SaveChangesAsync();
    }
    await using (var db = new MayakDb(opts))
    {
        var dev = await db.Devices.SingleAsync(x => x.Id == device1.Id);
        var identity = await db.Cluster.SingleAsync(x => x.Id == 1);
        var ready = await new AwgAdmissionService(db).CandidatesAsync(dev, identity, CancellationToken.None);
        Check("advertises only current acknowledged explicit candidate", ready.Count == 1 && ready[0].Id == server.Id &&
            ready[0].Host == server.Host && ready[0].Port == 51820 && ready[0].ExpectedEgressIps.SequenceEqual(new[] { "81.29.149.103" }));
        var row = await db.Servers.SingleAsync(x => x.Id == server.Id);
        row.AutoSelectEnabled = false;
        await db.SaveChangesAsync();
        var disabled = await new AwgAdmissionService(db).CandidatesAsync(dev, identity, CancellationToken.None);
        Check("disabled server is not advertised", disabled.Count == 0);
        row.AutoSelectEnabled = true;
        row.ProvisioningConfirmedRevision = identity.Revision - 1;
        await db.SaveChangesAsync();
        var stale = await new AwgAdmissionService(db).CandidatesAsync(dev, identity, CancellationToken.None);
        Check("stale provisioning revision is not advertised", stale.Count == 0);
        row.ProvisioningConfirmedRevision = identity.Revision;
        await db.SaveChangesAsync();
    }

    var attemptA = "attempt_A_00000001";
    var attemptB = "attempt_B_00000001";
    var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    async Task<(string? code, Guid? id)> TryAcquire(Guid accountId, Guid deviceId, string attempt)
    {
        await gate.Task;
        await using var db = new MayakDb(opts);
        var acc = await db.Accounts.SingleAsync(x => x.Id == accountId);
        var dev = await db.Devices.SingleAsync(x => x.Id == deviceId);
        var identity = await db.Cluster.SingleAsync(x => x.Id == 1);
        var result = await new AwgAdmissionService(db).AcquireAsync(acc, dev, server.Id, attempt, identity, CancellationToken.None);
        return (result.Code, result.Allocation?.Id);
    }
    var first = TryAcquire(account1.Id, device1.Id, attemptA);
    var second = TryAcquire(account2.Id, device2.Id, attemptB);
    gate.SetResult(true);
    var results = await Task.WhenAll(first, second);
    var winner = results.Single(x => x.id != null);
    var loser = results.Single(x => x.id == null);
    Check("concurrent last slot: exactly one allocation, loser FULL", results.Count(x => x.id != null) == 1 && loser.code == "FULL");

    var winnerAccount = winner.id == results[0].id ? account1 : account2;
    var winnerDevice = winner.id == results[0].id ? device1 : device2;
    var winnerAttempt = winner.id == results[0].id ? attemptA : attemptB;
    await using (var db = new MayakDb(opts))
    {
        var acc = await db.Accounts.SingleAsync(x => x.Id == winnerAccount.Id);
        var dev = await db.Devices.SingleAsync(x => x.Id == winnerDevice.Id);
        var identity = await db.Cluster.SingleAsync(x => x.Id == 1);
        var retry = await new AwgAdmissionService(db).AcquireAsync(acc, dev, server.Id, winnerAttempt, identity, CancellationToken.None);
        Check("lost response retry returns same allocation", retry.Code == null && retry.Allocation?.Id == winner.id);
    }

    var otherDevice = winnerDevice.Id == device1.Id ? device2 : device1;
    await using (var db = new MayakDb(opts))
    {
        var dev = await db.Devices.SingleAsync(x => x.Id == otherDevice.Id);
        var account = await db.Accounts.SingleAsync(x => x.Id == dev.AccountId);
        await new AwgAdmissionService(db).SetAllocationAsync(account, dev, account.AppKey!, dev.InstallationId!, dev.AwgPublicKey,
            winner.id!.Value, winnerAttempt, "release", CancellationToken.None);
    }
    await using (var db = new MayakDb(opts))
        Check("cross-device release cannot free allocation", await db.AwgAllocations.AnyAsync(a => a.Id == winner.id && a.ReleasedAt == null));

    await using (var db = new MayakDb(opts))
    {
        var dev = await db.Devices.SingleAsync(x => x.Id == winnerDevice.Id);
        var account = await db.Accounts.SingleAsync(x => x.Id == winnerAccount.Id);
        await new AwgAdmissionService(db).SetAllocationAsync(account, dev, account.AppKey!, dev.InstallationId!, dev.AwgPublicKey,
            winner.id!.Value, winnerAttempt, "release", CancellationToken.None);
        var identity = await db.Cluster.SingleAsync(x => x.Id == 1);
        var next = await new AwgAdmissionService(db).AcquireAsync(account, dev, server.Id, "attempt_C_00000001", identity, CancellationToken.None);
        await new AwgAdmissionService(db).SetAllocationAsync(account, dev, account.AppKey!, dev.InstallationId!, dev.AwgPublicKey,
            winner.id.Value, winnerAttempt, "release", CancellationToken.None);
        Check("stale release leaves newer allocation active", next.Code == null && await db.AwgAllocations.AnyAsync(a => a.Id == next.Allocation!.Id && a.ReleasedAt == null));
    }

    await using (var db = new MayakDb(opts))
    {
        var dev = await db.Devices.SingleAsync(x => x.Id == winnerDevice.Id);
        var account = await db.Accounts.SingleAsync(x => x.Id == winnerAccount.Id);
        var latest = await db.AwgAllocations.SingleAsync(a => a.DeviceId == winnerDevice.Id && a.ReleasedAt == null);
        await new AwgAdmissionService(db).SetAllocationAsync(account, dev, account.AppKey!, dev.InstallationId!, dev.AwgPublicKey,
            latest.Id, "attempt_C_00000001", "release", CancellationToken.None);
        var legacy = new Account { Name = "legacy" };
        db.Accounts.Add(legacy);
        db.Devices.Add(DeviceFor(legacy, false, "10.8.1.4"));
        await db.SaveChangesAsync();
        var devForLegacyCheck = await db.Devices.FirstAsync(d => d.AccountId == account2.Id);
        var identity = await db.Cluster.SingleAsync(x => x.Id == 1);
        var available = await new AwgAdmissionService(db).CandidatesAsync(devForLegacyCheck, identity, CancellationToken.None);
        Check("legacy unknown placement reserves shared server capacity", available.Count == 0);
    }

    Check("invalid or non-public egress rejected", !AwgAdmissionService.TryExpectedIps("[\"127.0.0.1\"]", out _) &&
        !AwgAdmissionService.TryExpectedIps("[\"203.0.113.4\"]", out _) && AwgAdmissionService.TryExpectedIps("[\"81.29.149.103\"]", out var valid) && valid.Length == 1);
    // Independent adverse cases, isolated from the author's original nine checks.
    await using(var db=new MayakDb(opts)) {
      await db.Servers.Where(s=>s.Id==server.Id).ExecuteUpdateAsync(u=>u.SetProperty(s=>s.NativeCapacity,100));
      var acc=await db.Accounts.SingleAsync(a=>a.Id==winnerAccount.Id);var dev=await db.Devices.SingleAsync(d=>d.Id==winnerDevice.Id);var identity=await db.Cluster.SingleAsync();
      var admission=new AwgAdmissionService(db);
      var initial=await admission.AcquireAsync(acc,dev,server.Id,"review_attempt_0000001",identity,CancellationToken.None);
      Check("review valid initial acquire",initial.Code==null);
      await db.Servers.Where(s=>s.Id==server.Id).ExecuteUpdateAsync(u=>u.SetProperty(s=>s.AutoSelectEnabled,false));
      var retryDisabled=await admission.AcquireAsync(acc,dev,server.Id,"review_attempt_0000001",identity,CancellationToken.None);
      Check("idempotent acquire cannot bypass disabled candidate",retryDisabled.Code!=null);
      await db.Servers.Where(s=>s.Id==server.Id).ExecuteUpdateAsync(u=>u.SetProperty(s=>s.AutoSelectEnabled,true).SetProperty(s=>s.ProvisioningConfirmedRevision,identity.Revision-1));
      var retryStale=await admission.AcquireAsync(acc,dev,server.Id,"review_attempt_0000001",identity,CancellationToken.None);
      Check("idempotent acquire cannot bypass stale ACK",retryStale.Code!=null);
      await db.Servers.Where(s=>s.Id==server.Id).ExecuteUpdateAsync(u=>u.SetProperty(s=>s.ProvisioningConfirmedRevision,identity.Revision));
      var retryOtherCandidate=await admission.AcquireAsync(acc,dev,Guid.NewGuid(),"review_attempt_0000001",identity,CancellationToken.None);
      Check("attempt cannot be rebound to different candidate",retryOtherCandidate.Code=="INVALID_REQUEST");
      await admission.ReconcileAsync(acc,dev,acc.AppKey!,dev.InstallationId!,dev.AwgPublicKey,"review_attempt_0000001",CancellationToken.None);
      var currentAllocation=await admission.AcquireAsync(acc,dev,server.Id,"review_attempt_0000002",identity,CancellationToken.None);
      Check("new cycle acquire succeeds",currentAllocation.Code==null);
      await admission.ReconcileAsync(acc,dev,acc.AppKey!,dev.InstallationId!,dev.AwgPublicKey,"review_attempt_0000001",CancellationToken.None); // delayed/repeated reconcile from previous cycle cannot free attempt 2
      Check("stale reconcile cannot free newer cycle allocation",await db.AwgAllocations.AnyAsync(a=>a.Id==currentAllocation.Allocation!.Id && a.ReleasedAt==null));
      await db.Devices.Where(d=>!d.AutoConnectManaged).ExecuteUpdateAsync(u=>u.SetProperty(d=>d.ServiceProtocol,"vless"));
      await db.Servers.Where(s=>s.Id==server.Id).ExecuteUpdateAsync(u=>u.SetProperty(s=>s.NativeCapacity,1));
      var reserveCandidates=await admission.CandidatesAsync(dev,identity,CancellationToken.None);
      Check("VLESS-only device does not consume AWG legacy reserve",reserveCandidates.Count==1);
    }

    await using(var db=new MayakDb(opts)) {
      await db.AwgAllocations.ExecuteDeleteAsync();
      var acc=await db.Accounts.SingleAsync(a=>a.Id==winnerAccount.Id);var dev=await db.Devices.SingleAsync(d=>d.Id==winnerDevice.Id);var identity=await db.Cluster.SingleAsync();
      var service=new AwgAdmissionService(db);
      Check("VLESS reserve check without existing own allocation",(await service.CandidatesAsync(dev,identity,CancellationToken.None)).Count==1);
      await db.Servers.ExecuteDeleteAsync();
      var legacyAcc=new Account{Name="capacity-legacy-AWG"};db.Accounts.Add(legacyAcc);db.Devices.Add(DeviceFor(legacyAcc,false,"10.8.1.200"));
      var ips=new[]{"1.1.1.1","8.8.8.8","9.9.9.9","4.2.2.2"};var rows=new List<Server>();
      for(int i=0;i<4;i++) {var row=ReadyServer(identity,i<3?1:2);row.Id=Guid.Parse("00000000-0000-0000-0000-"+(i+1).ToString("D12"));row.Host=ips[i];row.AgentTokenHash="capacity-token-"+i;row.ExpectedEgressIpsJson=JsonSerializer.Serialize(new[]{ips[i]});rows.Add(row);}
      db.Servers.AddRange(rows);await db.SaveChangesAsync();
      var candidates=await service.CandidatesAsync(dev,identity,CancellationToken.None);
      Check("advertisement skips three legacy-reserved full exits",candidates.Count==1 && candidates[0].Id==rows[3].Id);
      var result=await service.AcquireAsync(acc,dev,rows[3].Id,"review_capacity_000001",identity,CancellationToken.None);
      Console.WriteLine("OBSERVED advertised candidate acquire code="+(result.Code??"OK"));
      Check("advertised free fourth exit remains acquirable",result.Code==null && result.Allocation?.ServerId==rows[3].Id);
      if (result.Allocation == null) throw new InvalidOperationException("Fourth free exit must be acquired before all-full fixture.");
      await service.SetAllocationAsync(acc,dev,acc.AppKey!,dev.InstallationId!,dev.AwgPublicKey,
          result.Allocation.Id,"review_capacity_000001","release",CancellationToken.None);
      rows[3].NativeCapacity=1;
      await db.SaveChangesAsync();
      Check("all-full advertisement is empty",(await service.CandidatesAsync(dev,identity,CancellationToken.None)).Count==0);
      for (int i=0;i<rows.Count;i++) {
        var full=await service.AcquireAsync(acc,dev,rows[i].Id,"senior_full_attempt_"+i,identity,CancellationToken.None);
        Check("specific eligible full exit returns FULL #"+i,full.Code=="FULL" && full.Allocation==null);
      }
      rows[3].AutoSelectEnabled=false;
      await db.SaveChangesAsync();
      var disabled=await service.AcquireAsync(acc,dev,rows[3].Id,"senior_disabled_attempt",identity,CancellationToken.None);
      Check("specific disabled full exit returns NOT_READY before capacity",disabled.Code=="NOT_READY" && disabled.Allocation==null);
      Check("rejected full/disabled attempts allocate nothing",!await db.AwgAllocations.AnyAsync(a=>a.ReleasedAt==null));

    }

}
finally
{
    await using var admin = new NpgsqlConnection(adminCs);
    await admin.OpenAsync();
    await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)", admin);
    await drop.ExecuteNonQueryAsync();
}

if (failed != 0) Environment.ExitCode = 1;

static Device DeviceFor(Account account, bool managed, string ip) => new()
{
    Account = account, AccountId = account.Id, Name = "test", AwgPublicKey = Convert.ToBase64String(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray()),
    Ip = ip, XrayId = Guid.NewGuid().ToString(), InstallationId = Guid.NewGuid().ToString(), AutoConnectManaged = managed,
};

static Server ReadyServer(ClusterIdentity cluster, int capacity)
{
    var now = DateTime.UtcNow;
    return new Server
    {
        Name = "candidate", Host = "81.29.149.103", Role = ServerRoles.Exit, AgentTokenHash = "token-hash", AutoSelectEnabled = true,
        NativeCapacity = capacity, ExpectedEgressIpsJson = "[\"81.29.149.103\"]", ProvisioningStatus = "installed",
        ProvisionIdentityMatched = true, ProvisioningIdentityHash = ProvisioningPlanner.IdentityHash(cluster),
        ProvisioningConfirmedRevision = cluster.Revision, ProvisioningConfirmedAt = now, LastSeen = now,
        LastReport = JsonSerializer.Serialize(new AgentReport { AppliedRevision = cluster.Revision, ProvisioningProof = new ProvisioningRuntimeProof
            { AwgRunning = true, XrayRunning = true, ConfigurationLoaded = true, PostApplyCheckPassed = true } }),
    };
}
