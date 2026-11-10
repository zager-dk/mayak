using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Data.Common;
using Mayak.Api.Data;
using Mayak.Api.Provisioning;
using Mayak.Api.Services;
using Mayak.Api.Gateway;
using Mayak.Core.Agent;
using Mayak.Core.Models;
using Mayak.Core.Gateway;
using Mayak.Core.Export;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

if(args.Length!=1)throw new ArgumentException("local test PostgreSQL only");
var adminCs=new NpgsqlConnectionStringBuilder(args[0]){Database="postgres"}.ConnectionString;
var dbName="mayak_admissionreview_"+Guid.NewGuid().ToString("N")[..10];
await using(var a=new NpgsqlConnection(adminCs)){await a.OpenAsync();await using var c=new NpgsqlCommand($"CREATE DATABASE \"{dbName}\"",a);await c.ExecuteNonQueryAsync();}
var cs=new NpgsqlConnectionStringBuilder(args[0]){Database=dbName}.ConnectionString;
var opts=new DbContextOptionsBuilder<MayakDb>().UseNpgsql(cs).Options;
var failures=0;
void Check(string n,bool ok){Console.WriteLine((ok?"PASS ":"FAIL ")+n);if(!ok)failures++;}
using var rsa=RSA.Create(2048);
var keyFile=Path.Combine(Path.GetTempPath(),"mayak-admission-test-"+Guid.NewGuid().ToString("N")+".pem");
await File.WriteAllTextAsync(keyFile,rsa.ExportPkcs8PrivateKeyPem());
var owner=new Account{Name="existing-account",AppKey="synthetic-old-key",MaxDevices=10};
var dev=new Device{AccountId=owner.Id,Name="existing-device",InstallationId="review-installation",AwgPublicKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),Ip="10.8.1.2",XrayId=Guid.NewGuid().ToString()};
var identity=new ClusterIdentity{Id=1,Revision=7,AwgJson=JsonSerializer.Serialize(new ServerEndpoint{Host="81.29.149.103",Port=51820,ServerPublicKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),PresharedKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))})};
var exit=new Server{Name="exit",Host="81.29.149.103",Role="exit",AgentTokenHash="synthetic-agent",Active=true};
try {
 await using(var db=new MayakDb(opts)) {
  await db.GetService<IMigrator>().MigrateAsync("20261030120000_EmailPasswordCredentials");
  var jsonOptions=new JsonSerializerOptions();jsonOptions.Converters.Add(new JsonStringEnumConverter());
  await using(var conn=new NpgsqlConnection(cs)){await conn.OpenAsync();
   foreach(var row in new (string table,object item)[]{("Accounts",owner),("Devices",dev),("Cluster",identity),("Servers",exit)}) {
    await using var cmd=new NpgsqlCommand($"INSERT INTO \"{row.table}\" SELECT * FROM json_populate_record(NULL::\"{row.table}\", @j::json)",conn);cmd.Parameters.AddWithValue("j",JsonSerializer.Serialize(row.item,row.item.GetType(),jsonOptions));await cmd.ExecuteNonQueryAsync();
   }
  }
  await db.Database.MigrateAsync();
  var oldDevice=await db.Devices.SingleAsync();var oldServer=await db.Servers.SingleAsync();var oldAccount=await db.Accounts.SingleAsync();var oldCluster=await db.Cluster.SingleAsync();
  Check("populated premigration account/device/config preserved",oldDevice.Id==dev.Id && oldDevice.AwgPublicKey==dev.AwgPublicKey && oldDevice.Ip==dev.Ip && oldAccount.AppKey==owner.AppKey && oldCluster.AwgJson==identity.AwgJson);
  Check("migration defaults remain excluded and unclassified",!oldDevice.AutoConnectManaged && !oldServer.AutoSelectEnabled && oldServer.NativeCapacity==50 && oldServer.ExpectedEgressIpsJson=="[]");
  oldServer.AutoSelectEnabled=true;oldServer.ExpectedEgressIpsJson="[\"81.29.149.103\"]";Ack(oldServer,oldCluster);await db.SaveChangesAsync();
 }
 Environment.SetEnvironmentVariable("MAYAK_ConnectionStrings__Db",cs);Environment.SetEnvironmentVariable("MAYAK_Telegram__Polling","false");Environment.SetEnvironmentVariable("MAYAK_Probes__Enabled","false");Environment.SetEnvironmentVariable("MAYAK_Gateway__PrivateKeyPath",keyFile);
 await using var factory=new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b=>{b.UseContentRoot(AppContext.BaseDirectory);b.ConfigureLogging(l=>l.ClearProviders());});
 using var client=factory.CreateClient();
 JsonObject Config(bool opt)=>new(){["auth_data"]=new JsonObject{["api_key"]=owner.AppKey},["installation_uuid"]=dev.InstallationId,["public_key"]=dev.AwgPublicKey,["service_protocol"]="awg",["mayak_auto_connect"]=opt?1:0};
 async Task<JsonObject> Send(HttpClient target,string action,JsonObject data){var sealedReq=GatewayCrypto.SealRequest(data.ToJsonString(),rsa);using var response=await target.PostAsync("/gw/v1/"+action,new StringContent(sealedReq.Body,Encoding.UTF8,"application/json"));Check("encrypted HTTP transport status",response.IsSuccessStatusCode);return JsonNode.Parse(GatewayCrypto.OpenResponse(await response.Content.ReadAsByteArrayAsync(),sealedReq.Session))!.AsObject();}
 async Task<long> Acknowledge(){await using var db=new MayakDb(opts);var c=await db.Cluster.SingleAsync();var s=await db.Servers.SingleAsync();Ack(s,c);await db.SaveChangesAsync();return c.Revision;}
 var legacy=await Send(client,"config",Config(false));
 Check("legacy encrypted config shape remains compatible",legacy["config"] is JsonValue && legacy["mayak_connection"]==null && legacy["http_status"]==null);
 var before=await Acknowledge();
 var managed=await Send(client,"config",Config(true));
 Check("unchanged existing peer with current ACK gets candidates",managed["mayak_connection"]?["candidates"]?.AsArray().Count==1);
 await using(var db=new MayakDb(opts)){var rev=(await db.Cluster.SingleAsync()).Revision;Check("unchanged opt-in config does not bump peer revision",rev==before);}
 var retryBefore=await Acknowledge();
 var retryManaged=await Send(client,"config",Config(true));
 Check("retry after fresh agent ACK progresses to candidates",retryManaged["mayak_connection"]?["candidates"]?.AsArray().Count==1);
 await using(var db=new MayakDb(opts)){Check("retry revision is stable",(await db.Cluster.SingleAsync()).Revision==retryBefore);}
 await Acknowledge();
 var newPeerPublicKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
 var peerChangeRequest=Config(true);peerChangeRequest["public_key"]=newPeerPublicKey;
 long peerChangeRevision;await using(var db=new MayakDb(opts))peerChangeRevision=(await db.Cluster.SingleAsync()).Revision;
 var firstPeerRegistration=await Send(client,"config",peerChangeRequest);
 Check("new peer registration waits for its agent revision acknowledgement",firstPeerRegistration["code"]?.GetValue<string>()=="provisioning" && firstPeerRegistration["retry_after_ms"]?.GetValue<int>()==1500);
 await using(var db=new MayakDb(opts)){Check("new peer registration bumps revision once",(await db.Cluster.SingleAsync()).Revision==peerChangeRevision+1);}
 var acknowledgedPeerRevision=await Acknowledge();
 var peerRetry=await Send(client,"config",peerChangeRequest);
 Check("same request after peer ACK returns current candidates",peerRetry["mayak_connection"]?["candidates"]?.AsArray().Count==1);
 await using(var db=new MayakDb(opts)){Check("acknowledged peer retry does not bump revision",(await db.Cluster.SingleAsync()).Revision==acknowledgedPeerRevision);}
 // Rotate the account capability between device identification and locked acquire.
 var rotate=new RotateDuringLookup(cs,owner.Id);
 await using var rotatedFactory=new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b=>{b.UseContentRoot(AppContext.BaseDirectory);b.ConfigureLogging(l=>l.ClearProviders());b.ConfigureServices(s=>{foreach(var d in s.Where(x=>x.ServiceType==typeof(DbContextOptions<MayakDb>)).ToArray())s.Remove(d);s.AddDbContext<MayakDb>(o=>o.UseNpgsql(cs).AddInterceptors(rotate));});});
 using var rotatedClient=rotatedFactory.CreateClient();
 var acquire=Config(true);acquire["public_key"]=newPeerPublicKey;acquire["action"]="acquire";acquire["attempt_id"]="review_rotate_000001";acquire["candidate_id"]=exit.Id.ToString();
 var rotatedResult=await Send(rotatedClient,"admission",acquire);
 Check("rotation interceptor fired",rotate.Fired);
 Check("revoked old account capability denied under admission lock",rotatedResult["allocation_id"]==null);
 Check("revoked capability receives no AWG config",rotatedResult["config"]==null);
 if(rotatedResult["config"] is JsonValue configValue) {var decoded=JsonNode.Parse(VpnKeyCodec.Decode(configValue.GetValue<string>()));Check("old credential cannot receive replacement account capability",decoded?["auth_data"]?["api_key"]?.GetValue<string>()!="synthetic-rotated-key");}
 var deviceRotate=new RotateDeviceDuringLookup(cs,dev.Id);
 await using var deviceRotatedFactory=new WebApplicationFactory<MayakDb>().WithWebHostBuilder(b=>{b.UseContentRoot(AppContext.BaseDirectory);b.ConfigureLogging(l=>l.ClearProviders());b.ConfigureServices(s=>{foreach(var d in s.Where(x=>x.ServiceType==typeof(DbContextOptions<MayakDb>)).ToArray())s.Remove(d);s.AddDbContext<MayakDb>(o=>o.UseNpgsql(cs).AddInterceptors(deviceRotate));});});
 using var deviceRotatedClient=deviceRotatedFactory.CreateClient();
 var staleDeviceRequest=Config(true);staleDeviceRequest["auth_data"]!["api_key"]="synthetic-rotated-key";staleDeviceRequest["public_key"]=newPeerPublicKey;
 staleDeviceRequest["action"]="acquire";staleDeviceRequest["attempt_id"]="review_device_race_01";staleDeviceRequest["candidate_id"]=exit.Id.ToString();
 var staleDeviceResult=await Send(deviceRotatedClient,"admission",staleDeviceRequest);
 Check("device identity interceptor fired",deviceRotate.Fired);
 Check("rotated installation/public key cannot acquire or receive config",staleDeviceResult["allocation_id"]==null && staleDeviceResult["config"]==null);
 Console.WriteLine("RESULT failed="+failures);
} finally {File.Delete(keyFile);await using var a=new NpgsqlConnection(adminCs);await a.OpenAsync();await using var c=new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{dbName}\" WITH (FORCE)",a);await c.ExecuteNonQueryAsync();}
return failures==0?0:1;
static void Ack(Server s,ClusterIdentity c){var now=DateTime.UtcNow;s.ProvisioningStatus="installed";s.ProvisionIdentityMatched=true;s.ProvisioningIdentityHash=ProvisioningPlanner.IdentityHash(c);s.ProvisioningConfirmedRevision=c.Revision;s.ProvisioningConfirmedAt=now;s.LastSeen=now;s.LastReport=JsonSerializer.Serialize(new AgentReport{AppliedRevision=c.Revision,ProvisioningProof=new ProvisioningRuntimeProof{AwgRunning=true,XrayRunning=true,ConfigurationLoaded=true,PostApplyCheckPassed=true}});}
sealed class RotateDuringLookup(string cs,Guid accountId):DbCommandInterceptor {
 public bool Fired;
 public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand c,CommandExecutedEventData e,DbDataReader r,CancellationToken ct=default){
  if(!Fired && c.CommandText.Contains("FROM \"Devices\" AS d") && c.CommandText.Contains("InstallationId") && c.CommandText.Contains("AwgPublicKey") && c.Parameters.Cast<DbParameter>().Any(p=>p.Value?.ToString()=="review-installation")) {
   Fired=true;await using var conn=new NpgsqlConnection(cs);await conn.OpenAsync(ct);await using var tx=await conn.BeginTransactionAsync(ct);
   await using(var l=new NpgsqlCommand("SELECT pg_advisory_xact_lock(742019,1)",conn,tx))await l.ExecuteNonQueryAsync(ct);
   await using(var u=new NpgsqlCommand("UPDATE \"Accounts\" SET \"AppKey\"='synthetic-rotated-key' WHERE \"Id\"=@id",conn,tx)){u.Parameters.AddWithValue("id",accountId);await u.ExecuteNonQueryAsync(ct);}await tx.CommitAsync(ct);
  }return r;
 }
}
sealed class RotateDeviceDuringLookup(string cs,Guid deviceId):DbCommandInterceptor {
 public bool Fired;
 public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand c,CommandExecutedEventData e,DbDataReader r,CancellationToken ct=default){
  if(!Fired && c.CommandText.Contains("FROM \"Devices\" AS d") && c.CommandText.Contains("InstallationId") && c.CommandText.Contains("AwgPublicKey") && c.Parameters.Cast<DbParameter>().Any(p=>p.Value?.ToString()=="review-installation")) {
   Fired=true;await using var conn=new NpgsqlConnection(cs);await conn.OpenAsync(ct);await using var tx=await conn.BeginTransactionAsync(ct);
   await using(var l=new NpgsqlCommand("SELECT pg_advisory_xact_lock(742019,1)",conn,tx))await l.ExecuteNonQueryAsync(ct);
   await using(var u=new NpgsqlCommand("UPDATE \"Devices\" SET \"InstallationId\"='rotated-installation', \"AwgPublicKey\"=@pub WHERE \"Id\"=@id",conn,tx)){u.Parameters.AddWithValue("pub",Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));u.Parameters.AddWithValue("id",deviceId);await u.ExecuteNonQueryAsync(ct);}await tx.CommitAsync(ct);
  }return r;
 }
}
