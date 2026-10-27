using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Mayak.Api;
using Mayak.Api.Data;
using Mayak.Api.Endpoints;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;

// API Маяка. Настройки: appsettings.json, /etc/mayak/api.json, переменные окружения MAYAK_… (двойное подчёркивание = раздел).
// Команды обслуживания: mayak-api role <@telegram|id> <user|support|admin|owner>
//                       mayak-api add-server <exit|entry> <имя> <адрес> [город] [страна]
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args.Where(a => a.StartsWith("--")).ToArray() });
builder.Configuration.AddJsonFile("/etc/mayak/api.json", optional: true, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables("MAYAK_");

var cfg = builder.Configuration;
var connectionString = cfg.GetConnectionString("Db") ?? "Host=127.0.0.1;Database=mayak;Username=mayak;Password=mayak";
var publicUrl = (cfg["PublicUrl"] ?? "http://127.0.0.1:5080").TrimEnd('/');
var agentInstallUrl = cfg["AgentInstallUrl"] ?? "https://raw.githubusercontent.com/zager-dk/mayak/main/deploy/agent/install.sh";
var tgOptions = cfg.GetSection("Telegram").Get<TelegramOptions>() ?? new TelegramOptions();

builder.Services.AddDbContext<MayakDb>(o => o.UseNpgsql(connectionString));
builder.Services.AddScoped<ClusterService>();
builder.Services.AddSingleton(tgOptions);
builder.Services.AddSingleton<TelegramClient>();
if (cfg.GetValue("Telegram:Polling", true)) builder.Services.AddHostedService<TelegramBotService>();
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.PropertyNameCaseInsensitive = true;
});
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Add(System.Net.IPAddress.Loopback);
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("auth", http => RateLimitPartition.GetFixedWindowLimiter(
        http.Connection.RemoteIpAddress?.ToString() ?? "?",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) }));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
    db.Database.Migrate();
    var command = args.Where(a => !a.StartsWith("--")).ToArray();
    if (command.Length > 0) return await Cli.RunAsync(command, db, publicUrl, agentInstallUrl);
}

app.UseForwardedHeaders();
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", () => Results.Ok(new { ok = true, version = typeof(Program).Assembly.GetName().Version?.ToString(3) }));
AppEndpoints.Map(app);
AdminEndpoints.Map(app, publicUrl, agentInstallUrl);
AgentEndpoints.Map(app);

app.Run();
return 0;

public partial class Program { }
