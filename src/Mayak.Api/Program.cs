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
// Команда обслуживания — только первым аргументом; всё остальное — обычные параметры хоста (--urls, --contentRoot …).
var command = args.Length > 0 && !args[0].StartsWith("--") ? args : Array.Empty<string>();
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = command.Length > 0 ? Array.Empty<string>() : args });
builder.Configuration.AddJsonFile("/etc/mayak/api.json", optional: true, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables("MAYAK_");

var cfg = builder.Configuration;
var connectionString = cfg.GetConnectionString("Db") ?? "Host=127.0.0.1;Database=mayak;Username=mayak;Password=mayak";
var publicUrl = (cfg["PublicUrl"] ?? "http://127.0.0.1:5080").TrimEnd('/');
var agentInstallUrl = cfg["AgentInstallUrl"] ?? publicUrl + "/download/install-agent.sh";
// Сюда установщик кладёт собранного агента и его установочный скрипт; API раздаёт их серверам.
var distDir = cfg["DistDir"] ?? "/opt/mayak/dist";
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
    if (command.Length > 0) return await Cli.RunAsync(command, db, publicUrl, agentInstallUrl);
}

app.UseForwardedHeaders();
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/download/{file}", (string file) =>
{
    var allowed = new Dictionary<string, string> { ["mayak-agent"] = "application/octet-stream", ["install-agent.sh"] = "text/x-shellscript; charset=utf-8" };
    var path = Path.Combine(distDir, file);
    return allowed.TryGetValue(file, out var type) && File.Exists(path) ? Results.File(path, type, enableRangeProcessing: true) : Results.NotFound();
});
app.MapGet("/health", () => Results.Ok(new { ok = true, version = typeof(Program).Assembly.GetName().Version?.ToString(3) }));
AppEndpoints.Map(app);
AdminEndpoints.Map(app, publicUrl, agentInstallUrl);
AgentEndpoints.Map(app);

app.Run();
return 0;

public partial class Program { }
