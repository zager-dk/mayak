using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Mayak.Api;
using Mayak.Api.Data;
using Mayak.Api.Endpoints;
using Mayak.Api.Gateway;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Api.Provisioning;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;

// API Маяка. Настройки: appsettings.json, /etc/mayak/api.json, переменные окружения MAYAK_… (двойное подчёркивание = раздел).
// Команды обслуживания: mayak-api role <@telegram|id> <user|support|admin|owner>
//                       mayak-api add-server <exit|entry> <имя> <адрес> [город] [страна]
// Команда обслуживания — только первым аргументом; всё остальное — обычные параметры хоста (--urls, --contentRoot …).
var command = args.Length > 0 && !args[0].StartsWith("--") ? args : Array.Empty<string>();
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = command.Length > 0 ? Array.Empty<string>() : args });
// Hosting.Diagnostics logs Request.Path verbatim, which would expose the capability token in /sub/{token}.
builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.None);
builder.Configuration.AddJsonFile("/etc/mayak/api.json", optional: true, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables("MAYAK_");

var cfg = builder.Configuration;
var connectionString = cfg.GetConnectionString("Db") ?? "Host=127.0.0.1;Database=mayak;Username=mayak;Password=mayak";
var publicUrl = (cfg["PublicUrl"] ?? "http://127.0.0.1:5080").TrimEnd('/');
var agentInstallUrl = cfg["AgentInstallUrl"] ?? publicUrl + "/download/install-agent.sh";
// Сюда установщик кладёт собранного агента и его установочный скрипт; API раздаёт их серверам.
var distDir = cfg["DistDir"] ?? "/opt/mayak/dist";
var tgOptions = cfg.GetSection("Telegram").Get<TelegramOptions>() ?? new TelegramOptions();
// Кабинет — по отдельному адресу; главная страница домена остаётся нейтральной.
tgOptions.SiteUrl ??= publicUrl + "/my/";
tgOptions.PublicUrl ??= publicUrl;

builder.Services.AddDbContext<MayakDb>(o => o.UseNpgsql(connectionString));
builder.Services.AddScoped<ClusterService>();
builder.Services.AddScoped<DeviceAccessService>();
builder.Services.AddSingleton<IProvisioningBackend, SshProvisioningBackend>();
builder.Services.AddSingleton<ProvisioningCoordinator>();
builder.Services.AddSingleton(tgOptions);
// Ключ шлюза для приложения Маяк; создаёт установщик (openssl), без него шлюз выключен.
builder.Services.AddSingleton(new GatewayKeys(cfg["Gateway:PrivateKeyPath"] ?? "/etc/mayak/gateway.pem"));
builder.Services.AddSingleton<TelegramClient>();
if (cfg.GetValue("Telegram:Polling", true)) builder.Services.AddHostedService<TelegramBotService>();
// Проверка доступности серверов с машины API (этап A, PROBES_PLAN.md): фоном раз в 5 минут (Probes:IntervalSeconds)
// и по кнопке в админке. Фон выключается Probes:Background=false, всё целиком — Probes:Enabled=false.
if (cfg.GetValue("Probes:Enabled", true) && cfg.GetValue("Probes:Background", true)) builder.Services.AddHostedService<ServerProbeService>();
// Срок хранения истории использования (статистика админки): 14 дней по часам, 1 год по суткам. Usage:Retention=false — выключить.
if (cfg.GetValue("Usage:Retention", true)) builder.Services.AddHostedService<UsageRetentionService>();
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
    // Выдача ключа устройства: каждый вызов меняет ключ, пишет аудит и может слать уведомления — не чаще 10 раз в минуту на сеанс.
    o.AddPolicy("device-key", http => RateLimitPartition.GetFixedWindowLimiter(
        Tokens.FromRequest(http.Request) is { Length: > 0 } bearer ? Tokens.Hash(bearer) : http.Connection.RemoteIpAddress?.ToString() ?? "?",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, cfg.GetValue("Devices:KeyRequestsPerMinute", 10)), Window = TimeSpan.FromMinutes(1) }));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MayakDb>();
    db.Database.Migrate();
    var interrupted = new[] { "queued", "preflight", "installing", "installing_awg", "installing_xray", "installing_agent", "awaiting_agent", "syncing" };
    await db.Servers.Where(s => s.ProvisioningStatus != null && interrupted.Contains(s.ProvisioningStatus))
        .ExecuteUpdateAsync(u => u.SetProperty(s => s.ProvisioningStatus, "interrupted")
            .SetProperty(s => s.ProvisioningMessage, "API перезапущен; SSH учётные данные удалены. Повторите проверку и безопасно начните новую установку.")
            .SetProperty(s => s.ProvisioningUpdatedAt, DateTime.UtcNow));
    if (command.Length > 0) return await Cli.RunAsync(command, db, publicUrl, agentInstallUrl);
}

app.UseForwardedHeaders();
app.Use(async (http, next) =>
{
    if (http.Request.Path.StartsWithSegments("/api") || http.Request.Path.StartsWithSegments("/gw/v1") || http.Request.Path.StartsWithSegments("/sub"))
    {
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";
    }
    await next();
});
app.UseRateLimiter();
app.UseDefaultFiles();
// Страницы и ресурсы сайта без версий в именах: браузер хранит копию, но перед показом сверяет её с сервером
// (ETag/Last-Modified, ответ 304), поэтому обновлённая главная и кабинет видны сразу.
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx => ctx.Context.Response.Headers.CacheControl = "no-cache",
});

app.MapGet("/download/{file}", (string file) =>
{
    var allowed = new Dictionary<string, string> { ["mayak-agent"] = "application/octet-stream", ["install-agent.sh"] = "text/x-shellscript; charset=utf-8" };
    var path = Path.Combine(distDir, file);
    return allowed.TryGetValue(file, out var type) && File.Exists(path) ? Results.File(path, type, enableRangeProcessing: true) : Results.NotFound();
});
app.MapGet("/health", () => Results.Ok(new { ok = true, version = typeof(Program).Assembly.GetName().Version?.ToString(3) }));
AppEndpoints.Map(app);
EmailAuthEndpoints.Map(app);
AdminEndpoints.Map(app, publicUrl, agentInstallUrl);
ProvisioningEndpoints.Map(app, publicUrl);
AgentEndpoints.Map(app);
GatewayEndpoints.Map(app);

app.Run();
return 0;

public partial class Program { }
