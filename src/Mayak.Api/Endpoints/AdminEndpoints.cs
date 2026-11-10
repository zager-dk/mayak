using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Api.Telegram;
using Mayak.Api.Provisioning;
using Mayak.Core.Models;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api.Endpoints;

public sealed record AccountCreate(string Name, string? Note, int? MaxDevices, int? DownMbps, int? UpMbps, DateTime? PaidUntil);
public sealed record AccountPatch(string? Name, string? Note, bool? Enabled, DateTime? PaidUntil, bool? ClearPaidUntil,
    int? MaxDevices, int? DownMbps, int? UpMbps, string? Role);
public sealed record DeviceCreate(string Name, DeviceKind Kind);
public sealed record DevicePatch(string? Name, bool? Enabled, int? DownMbps, int? UpMbps, bool? ClearLimits);
public sealed record ServerCreate(string Name, string Role, string Host, string? City, string? Country, string? CountryCode, string? Fact, string? PhotoUrl);
public sealed record ServerPatch(string? Name, string? Host, string? City, string? Country, string? CountryCode, string? Fact, string? PhotoUrl,
    bool? Active, Guid? TargetExitId, bool? ClearTarget, bool? AutoSelectEnabled = null, int? NativeCapacity = null, string[]? ExpectedEgressIps = null);
/// <summary>XrayClientFingerprint: "" — сбросить (по умолчанию firefox), иначе одно из ClusterService.ClientFingerprints.</summary>
public sealed record ClusterPatch(string? PublicHost, string? Dns1, string? Dns2, string? Title, string? XrayClientFingerprint = null);
public sealed record ExitEndpointCreate(Guid ServerId, string Host, int Port, string PublicKey, string Sni, string ShortId, string? Flow, string? Transport, int CapacitySlots, bool AllowNewConnections,
    string? Fingerprint = null, string? XhttpPath = null, string? XhttpHost = null, string? XhttpMode = null);
public sealed record ExitEndpointPatch(string? Host, int? Port, string? PublicKey, string? Sni, string? ShortId, string? Flow, string? Transport, int? CapacitySlots, bool? AllowNewConnections,
    string? Fingerprint = null, string? XhttpPath = null, string? XhttpHost = null, string? XhttpMode = null);

/// <summary>Администрирование: люди, устройства, серверы, общие настройки.</summary>
public static class AdminEndpoints
{
    public static void Map(WebApplication app, string publicUrl, string agentInstallUrl)
    {
        var g = app.MapGroup("/api/admin").AddEndpointFilter(new RequireAccount(Roles.Support));
        var admin = app.MapGroup("/api/admin").AddEndpointFilter(new RequireAccount(Roles.Admin));

        g.MapGet("/overview", async (MayakDb db) =>
        {
            var now = DateTime.UtcNow;
            var online = now.AddMinutes(-3);
            return Results.Ok(new
            {
                accounts = await db.Accounts.CountAsync(),
                waiting = await db.Accounts.CountAsync(a => !a.Enabled),
                devices = await db.Devices.CountAsync(),
                online = await db.Devices.CountAsync(d => d.LastHandshake > online),
                servers = (await db.Servers.OrderBy(s => s.Role).ThenBy(s => s.Name).ToListAsync()).Select(ServerView),
            });
        });

        // ───── Люди ─────
        g.MapGet("/accounts", async (string? q, MayakDb db) =>
        {
            var query = db.Accounts.Include(a => a.Devices).AsQueryable();
            if (!string.IsNullOrWhiteSpace(q))
            {
                var s = q.Trim().ToLower();
                query = query.Where(a => a.Name.ToLower().Contains(s) || (a.TelegramUsername != null && a.TelegramUsername.ToLower().Contains(s)) || (a.Email != null && a.Email.ToLower().Contains(s)));
            }
            var list = await query.OrderBy(a => a.Enabled).ThenBy(a => a.Name).Take(500).ToListAsync();
            return Results.Ok(list.Select(a => new { account = AppEndpoints.AccountView(a), a.Note, a.Legacy, a.CreatedAt, devices = a.Devices.Select(AppEndpoints.DeviceView) }));
        });

        g.MapPost("/accounts", async (AccountCreate body, HttpContext http, MayakDb db) =>
        {
            if (string.IsNullOrWhiteSpace(body.Name)) return Results.BadRequest(new { error = "Нужно имя" });
            var acc = new Account
            {
                Name = body.Name.Trim(),
                Note = body.Note?.Trim() ?? "",
                MaxDevices = body.MaxDevices ?? 3,
                DownMbps = body.DownMbps ?? 35,
                UpMbps = body.UpMbps ?? 35,
                PaidUntil = body.PaidUntil?.ToUniversalTime(),
            };
            db.Accounts.Add(acc);
            Audit(db, http, "account.create", acc.Name);
            await db.SaveChangesAsync();
            return Results.Ok(AppEndpoints.AccountView(acc));
        });

        g.MapPatch("/accounts/{id:guid}", async (Guid id, AccountPatch body, HttpContext http, MayakDb db, ClusterService cluster, TelegramClient tg, TelegramOptions tgOpt) =>
        {
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            var me = http.Me();
            await db.Entry(acc).ReloadAsync(http.RequestAborted);
            if (body.Role != null)
            {
                if (me.Role != Roles.Owner) return Results.Json(new { error = "Роли назначает только владелец" }, statusCode: 403);
                if (!Roles.All.Contains(body.Role)) return Results.BadRequest(new { error = "Неизвестная роль" });
                acc.Role = body.Role;
            }
            if (body.Name != null) acc.Name = body.Name.Trim();
            if (body.Note != null) acc.Note = body.Note.Trim();
            bool approved = body.Enabled == true && !acc.Enabled;
            if (body.Enabled != null) acc.Enabled = body.Enabled.Value;
            if (body.ClearPaidUntil == true) acc.PaidUntil = null;
            else if (body.PaidUntil != null) acc.PaidUntil = body.PaidUntil.Value.ToUniversalTime();
            if (body.MaxDevices != null) acc.MaxDevices = Math.Max(0, body.MaxDevices.Value);
            if (body.DownMbps != null) acc.DownMbps = Math.Max(0, body.DownMbps.Value);
            if (body.UpMbps != null) acc.UpMbps = Math.Max(0, body.UpMbps.Value);
            Audit(db, http, "account.update", $"{acc.Id} {acc.Name}");
            await db.SaveChangesAsync();
            if (!acc.Enabled || acc.PaidUntil is DateTime endsAt && endsAt <= DateTime.UtcNow)
                await db.AwgAllocations.Where(a => a.ReleasedAt == null && db.Devices.Any(d => d.Id == a.DeviceId && d.AccountId == acc.Id))
                    .ExecuteUpdateAsync(u => u.SetProperty(a => a.ReleasedAt, DateTime.UtcNow), http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            if (approved && acc.TelegramId is long tid && tg.Enabled)
            {
                try { await tg.SendAsync(tid, $"Доступ к Маяку одобрен — можно подключаться.\nКлюч для приложения: {tgOpt.SiteUrl}", http.RequestAborted); }
                catch (Exception) { /* сообщение не критично */ }
            }
            return Results.Ok(AppEndpoints.AccountView(acc));
        });

        // Ссылка-приглашение: человек входит по ней через Telegram и получает этот аккаунт со всеми устройствами.
        g.MapPost("/accounts/{id:guid}/invite", async (Guid id, HttpContext http, MayakDb db) =>
        {
            var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            await db.Invites.Where(i => i.AccountId == id && i.UsedAt == null).ExecuteDeleteAsync();
            var code = Tokens.New(12);
            db.Invites.Add(new Invite { CodeHash = Tokens.Hash(code), AccountId = id, CreatedBy = http.Me().Id });
            Audit(db, http, "invite.create", acc.Name);
            await db.SaveChangesAsync();
            return Results.Ok(new { url = $"{publicUrl}/my/?invite={code}", expiresInDays = 14 });
        });

        admin.MapDelete("/accounts/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            if (acc.Role == Roles.Owner) return Results.BadRequest(new { error = "Владельца удалить нельзя" });
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            db.Accounts.Remove(acc);
            Audit(db, http, "account.delete", $"{acc.Id} {acc.Name}");
            await db.SaveChangesAsync(http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        // ───── Устройства ─────
        g.MapPost("/accounts/{id:guid}/devices", async (Guid id, DeviceCreate body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = await db.Accounts.Include(a => a.Devices).FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            if (string.IsNullOrWhiteSpace(body.Name)) return Results.BadRequest(new { error = "Нужно название устройства" });
            try
            {
                var d = await cluster.CreateManagedDeviceAsync(acc, body.Name.Trim(), body.Kind, http.RequestAborted);
                Audit(db, http, "device.create", $"{acc.Name} / {d.Name}");
                await db.SaveChangesAsync();
                var (key, conf) = await cluster.BuildFilesAsync(d, acc, http.RequestAborted);
                return Results.Ok(new { device = AppEndpoints.DeviceView(d), vpnKey = key, conf });
            }
            catch (DeviceLimitException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: 409);
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        g.MapGet("/devices/{id:guid}/files", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var d = await db.Devices.Include(x => x.Account).FirstOrDefaultAsync(x => x.Id == id);
            if (d?.Account == null) return Results.NotFound();
            try
            {
                if (d.ServiceProtocol == "vless")
                    return Results.Ok(await cluster.BuildDeviceFilesAsync(d, d.Account, http.RequestAborted));
                var (key, conf) = await cluster.BuildFilesAsync(d, d.Account, http.RequestAborted);
                return Results.Ok(new { vpnKey = key, conf });
            }
            catch (PoolDeliveryException ex)
            {
                return Results.Json(new { error = ex.Message }, statusCode: ex.StatusCode);
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        g.MapPatch("/devices/{id:guid}", async (Guid id, DevicePatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id);
            if (d == null) return Results.NotFound();
            if (body.Name != null) d.Name = body.Name.Trim();
            if (body.Enabled != null) d.Enabled = body.Enabled.Value;
            if (body.ClearLimits == true) { d.DownMbps = null; d.UpMbps = null; }
            if (body.DownMbps != null) d.DownMbps = Math.Max(0, body.DownMbps.Value);
            if (body.UpMbps != null) d.UpMbps = Math.Max(0, body.UpMbps.Value);
            Audit(db, http, "device.update", $"{d.Id} {d.Name}");
            await db.SaveChangesAsync();
            if (body.Enabled == false)
                await db.AwgAllocations.Where(a => a.DeviceId == d.Id && a.ReleasedAt == null)
                    .ExecuteUpdateAsync(u => u.SetProperty(a => a.ReleasedAt, DateTime.UtcNow), http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.Ok(AppEndpoints.DeviceView(d));
        });

        g.MapDelete("/devices/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id);
            if (d == null) return Results.NotFound();
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            db.Devices.Remove(d);
            Audit(db, http, "device.delete", $"{d.Id} {d.Name}");
            await db.SaveChangesAsync(http.RequestAborted);
            await cluster.ReconcilePoolCredentialsAsync(DateTime.UtcNow, http.RequestAborted);
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        // ───── Серверы ─────
        g.MapGet("/servers", async (MayakDb db) =>
            Results.Ok((await db.Servers.OrderBy(s => s.Role).ThenBy(s => s.Name).ToListAsync()).Select(ServerView)));

        // Доступность серверов с машины API: последний результат, доля успешных, задержка и полоса истории (48 корзин).
        g.MapGet("/probes", async (int? hours, MayakDb db, HttpContext http, IConfiguration cfg) =>
        {
            var window = TimeSpan.FromHours(Math.Clamp(hours ?? 24, 1, 168));
            var now = DateTime.UtcNow;
            var from = now - window;
            var probes = await db.ServerProbes.AsNoTracking().Where(p => p.At > from).ToListAsync(http.RequestAborted);
            var servers = probes.GroupBy(p => p.ServerId).ToDictionary(g => g.Key.ToString(),
                g => ServerProbeStats.Summarize(g, now, window, 48));
            return Results.Ok(new { at = now, hours = (int)window.TotalHours, background = cfg.GetValue("Probes:Enabled", true) && cfg.GetValue("Probes:Background", true), servers });
        });

        // Проверить сейчас: все серверы или один (?serverId=…). Один проход за раз; длится не больше ~10 с.
        g.MapPost("/probes/run", async (Guid? serverId, MayakDb db, HttpContext http) =>
        {
            if (serverId is Guid sid && !await db.Servers.AnyAsync(s => s.Id == sid, http.RequestAborted)) return Results.NotFound();
            var results = await ServerProbeService.RunOnceAsync(db, serverId, http.RequestAborted);
            if (results == null) return Results.Conflict(new { error = "Проверка уже идёт, подождите несколько секунд." });
            return Results.Ok(new { at = DateTime.UtcNow, count = results.Count });
        });

        g.MapGet("/exit-endpoints", async (MayakDb db, ClusterService cluster, IConfiguration cfg, HttpContext http) =>
        {
            return await cluster.WithPoolStateAsync(async now => Results.Ok(new { enabled = cfg.GetValue("VlessPool:Enabled", false), endpoints = await db.ExitEndpoints.Include(e => e.Server).OrderBy(e => e.Id).Select(e => new
            { e.Id, e.ServerId, server = e.Server!.Name, e.Host, e.Port, e.PublicKey, e.Sni, e.ShortId, e.Flow, e.Transport, e.Fingerprint, e.XhttpPath, e.XhttpHost, e.XhttpMode, e.IdentityVersion,
                e.AllowNewConnections, e.CapacitySlots, e.OccupiedSlots, ready = ClusterService.IsPoolReady(e, now), e.ProtocolReportReceivedAt }).ToListAsync() }), http.RequestAborted);
        });

        admin.MapPost("/exit-endpoints", async (ExitEndpointCreate body, HttpContext http, MayakDb db, ClusterService cluster, IConfiguration cfg) =>
        {
            if (!cfg.GetValue("VlessPool:Enabled", false)) return Results.StatusCode(404);
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            if (!await db.Servers.AnyAsync(s => s.Id == body.ServerId && s.Role == ServerRoles.Exit)) return Results.BadRequest(new { error = "Нужен существующий сервер выхода" });
            if (!ValidEndpoint(body.Host, body.Port, body.PublicKey, body.Sni, body.ShortId, body.Flow ?? "", body.Transport ?? "tcp", body.CapacitySlots, body.XhttpPath ?? "/", body.XhttpMode ?? "auto")) return Results.BadRequest(new { error = "Некорректные публичные параметры или capacitySlots" });
            if (await db.ExitEndpoints.AnyAsync(e => e.ServerId == body.ServerId)) return Results.Conflict(new { error = "Для выхода уже настроен endpoint" });
            var e = new ExitEndpoint { ServerId = body.ServerId, Host = body.Host.Trim(), Port = body.Port, PublicKey = body.PublicKey.Trim(), Sni = body.Sni.Trim(), ShortId = body.ShortId.Trim(), Flow = body.Flow?.Trim() ?? "", Transport = body.Transport?.Trim() ?? "tcp", CapacitySlots = body.CapacitySlots, AllowNewConnections = body.AllowNewConnections,
                Fingerprint = body.Fingerprint?.Trim() ?? "chrome", XhttpPath = body.XhttpPath ?? "/", XhttpHost = body.XhttpHost?.Trim() ?? "", XhttpMode = body.XhttpMode?.Trim() ?? "auto" };
            db.ExitEndpoints.Add(e); Audit(db, http, "exit-endpoint.create", e.ServerId.ToString()); await db.SaveChangesAsync(); await tx.CommitAsync(http.RequestAborted); await cluster.BumpAsync(http.RequestAborted);
            return Results.Ok(new { e.Id, e.IdentityVersion });
        });

        admin.MapPatch("/exit-endpoints/{id:guid}", async (Guid id, ExitEndpointPatch body, HttpContext http, MayakDb db, ClusterService cluster, IConfiguration cfg) =>
        {
            if (!cfg.GetValue("VlessPool:Enabled", false)) return Results.StatusCode(404);
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            var e = await db.ExitEndpoints.FirstOrDefaultAsync(x => x.Id == id); if (e == null) return Results.NotFound();
            var host = body.Host ?? e.Host; var port = body.Port ?? e.Port; var key = body.PublicKey ?? e.PublicKey; var sni = body.Sni ?? e.Sni; var shortId = body.ShortId ?? e.ShortId; var flow = body.Flow ?? e.Flow; var transport = body.Transport ?? e.Transport; var cap = body.CapacitySlots ?? e.CapacitySlots;
            var fingerprint = body.Fingerprint ?? e.Fingerprint; var xhttpPath = body.XhttpPath ?? e.XhttpPath; var xhttpHost = body.XhttpHost ?? e.XhttpHost; var xhttpMode = body.XhttpMode ?? e.XhttpMode;
            if (!ValidEndpoint(host, port, key, sni, shortId, flow, transport, cap, xhttpPath, xhttpMode) || cap < e.OccupiedSlots) return Results.BadRequest(new { error = "Некорректные параметры или capacity ниже уже занятых слотов" });
            bool identityChanged = host != e.Host || port != e.Port || key != e.PublicKey || sni != e.Sni || shortId != e.ShortId || flow != e.Flow || transport != e.Transport || fingerprint != e.Fingerprint || xhttpPath != e.XhttpPath || xhttpHost != e.XhttpHost || xhttpMode != e.XhttpMode;
            e.Host = host.Trim(); e.Port = port; e.PublicKey = key.Trim(); e.Sni = sni.Trim(); e.ShortId = shortId.Trim(); e.Flow = flow.Trim(); e.Transport = transport.Trim(); e.Fingerprint = fingerprint.Trim(); e.XhttpPath = xhttpPath; e.XhttpHost = xhttpHost.Trim(); e.XhttpMode = xhttpMode.Trim(); e.CapacitySlots = cap;
            if (body.AllowNewConnections != null) e.AllowNewConnections = body.AllowNewConnections.Value;
            if (identityChanged) { e.IdentityVersion++; e.RuntimeReady = false; e.ConfigValid = false; e.SelfTestPassed = false; e.ProtocolReportReceivedAt = null; }
            Audit(db, http, "exit-endpoint.update", id.ToString()); await db.SaveChangesAsync(); await tx.CommitAsync(http.RequestAborted); await cluster.BumpAsync(http.RequestAborted);
            return Results.Ok(new { e.Id, e.IdentityVersion });
        });

        admin.MapPost("/servers", async (ServerCreate body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            if (body.Role is not (ServerRoles.Exit or ServerRoles.Entry)) return Results.BadRequest(new { error = "role: exit или entry" });
            if (string.IsNullOrWhiteSpace(body.Host)) return Results.BadRequest(new { error = "Нужен адрес сервера" });
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            await ProvisioningGuards.AcquireHostMutationLockAsync(db, http.RequestAborted);
            var host = ProvisioningGuards.CanonicalHostKey(body.Host);
            if (string.IsNullOrWhiteSpace(host)) return Results.BadRequest(new { error = "Нужен адрес сервера" });
            if (await ProvisioningGuards.HostExistsAsync(db, host, null, http.RequestAborted))
                return Results.Conflict(new { error = "Адрес уже зарегистрирован; проверьте существующую запись сервера." });
            var token = Tokens.New();
            var s = new Server
            {
                Name = string.IsNullOrWhiteSpace(body.Name) ? host : body.Name.Trim(),
                Role = body.Role,
                Host = host,
                City = body.City?.Trim() ?? "",
                Country = body.Country?.Trim() ?? "",
                CountryCode = body.CountryCode?.Trim().ToLowerInvariant() ?? "",
                Fact = body.Fact?.Trim() ?? "",
                PhotoUrl = body.PhotoUrl,
                AgentTokenHash = Tokens.Hash(token),
                Active = body.Role == ServerRoles.Exit && !await db.Servers.AnyAsync(x => x.Role == ServerRoles.Exit),
            };
            db.Servers.Add(s);
            Audit(db, http, "server.create", $"{s.Role} {s.Name} {s.Host}");
            await db.SaveChangesAsync();
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.Ok(new { server = ServerView(s), agentToken = token, install = InstallCommand(agentInstallUrl, publicUrl, token), installDryRun = InstallCommand(agentInstallUrl, publicUrl, token) + " --dry-run" });
        });

        admin.MapPost("/servers/{id:guid}/token", async (Guid id, HttpContext http, MayakDb db) =>
        {
            var s = await db.Servers.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound();
            var token = Tokens.New();
            s.AgentTokenHash = Tokens.Hash(token);
            Audit(db, http, "server.token", s.Name);
            await db.SaveChangesAsync();
            return Results.Ok(new { agentToken = token, install = InstallCommand(agentInstallUrl, publicUrl, token), installDryRun = InstallCommand(agentInstallUrl, publicUrl, token) + " --dry-run" });
        });

        admin.MapPatch("/servers/{id:guid}", async (Guid id, ServerPatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            await using var tx = await db.Database.BeginTransactionAsync(http.RequestAborted);
            if (body.Host != null || body.Active == true || body.TargetExitId != null || body.AutoSelectEnabled != null || body.NativeCapacity != null || body.ExpectedEgressIps != null)
                await ProvisioningGuards.AcquireHostMutationLockAsync(db, http.RequestAborted);
            if (body.AutoSelectEnabled != null || body.NativeCapacity != null || body.ExpectedEgressIps != null)
                await DeviceWriteLock.AcquireAsync(db, http.RequestAborted);
            var s = await db.Servers.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound();
            if (body.AutoSelectEnabled == true && s.Role != ServerRoles.Exit)
                return Results.BadRequest(new { error = "Авто-выбор можно включить только для выхода" });
            if (body.NativeCapacity is int nativeCapacity && nativeCapacity is < 1 or > 10000)
                return Results.BadRequest(new { error = "nativeCapacity должен быть от 1 до 10000" });
            string? egressJson = null;
            if (body.ExpectedEgressIps is { } egressIps)
            {
                var candidateJson = System.Text.Json.JsonSerializer.Serialize(egressIps);
                if (!AwgAdmissionService.TryExpectedIps(candidateJson, out var validated) || validated.Length != egressIps.Length)
                    return Results.BadRequest(new { error = "expectedEgressIps должен содержать уникальные публичные IPv4 адреса" });
                egressJson = System.Text.Json.JsonSerializer.Serialize(validated);
            }
            if (body.AutoSelectEnabled == true || body.ExpectedEgressIps != null && s.AutoSelectEnabled)
            {
                var egress = egressJson ?? s.ExpectedEgressIpsJson;
                if (!AwgAdmissionService.TryExpectedIps(egress, out var validated) || validated.Length == 0)
                    return Results.BadRequest(new { error = "Для авто-выбора нужен подтверждённый expectedEgressIps" });
                var identity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, http.RequestAborted);
                if (body.AutoSelectEnabled == true && !ProvisioningGuards.IsReady(s, identity, DateTime.UtcNow))
                    return Results.Conflict(new { error = "Выход не готов по текущим provisioning identity/revision и свежему отчёту агента" });
            }
            var requestedHost = body.Host == null ? s.Host : ProvisioningGuards.CanonicalHostKey(body.Host);
            if (body.Host != null)
            {
                if (string.IsNullOrWhiteSpace(requestedHost)) return Results.BadRequest(new { error = "Нужен адрес сервера" });
                if (s.ProvisioningStatus != null && requestedHost != ProvisioningGuards.CanonicalHostKey(s.Host))
                    return Results.Conflict(new { error = "Адрес установленного через provisioning сервера закреплён за проверенным SSH fingerprint и identity." });
            }
            // Activation must also reject duplicates already persisted by an
            // older version, even when this PATCH does not contain a host.
            if ((body.Host != null || body.Active == true) && await ProvisioningGuards.HostExistsAsync(db, requestedHost, id, http.RequestAborted))
                return Results.Conflict(new { error = "Адрес уже зарегистрирован; проверьте существующую запись сервера." });
            if (body.Active == true && s.ProvisioningStatus != null)
            {
                var actor = http.Me();
                if (!actor.Enabled || actor.Role is not (Roles.Admin or Roles.Owner))
                    return Results.Json(new { error = "Для активации новой установки нужен активный администратор или владелец." }, statusCode: 403);
                var currentIdentity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, http.RequestAborted);
                if (!ProvisioningGuards.IsReady(s, currentIdentity, DateTime.UtcNow))
                    return Results.Conflict(new { error = "Новая установка не имеет свежего подтверждения identity, текущей ревизии и работы AWG/Xray." });
            }
            if (body.Name != null) s.Name = body.Name.Trim();
            if (body.Host != null) s.Host = requestedHost;
            if (body.City != null) s.City = body.City.Trim();
            if (body.Country != null) s.Country = body.Country.Trim();
            if (body.CountryCode != null) s.CountryCode = body.CountryCode.Trim().ToLowerInvariant();
            if (body.Fact != null) s.Fact = body.Fact.Trim();
            if (body.PhotoUrl != null) s.PhotoUrl = body.PhotoUrl.Length == 0 ? null : body.PhotoUrl;
            if (body.AutoSelectEnabled is bool autoSelect) s.AutoSelectEnabled = autoSelect;
            if (body.NativeCapacity is int capacity) s.NativeCapacity = capacity;
            if (egressJson != null) s.ExpectedEgressIpsJson = egressJson;
            if (body.Active == true && s.Role == ServerRoles.Exit)
            {
                await db.Servers.Where(x => x.Role == ServerRoles.Exit && x.Id != s.Id).ExecuteUpdateAsync(u => u.SetProperty(x => x.Active, false));
                s.Active = true;
                // Входы переключаются на новый активный выход.
                await db.Servers.Where(x => x.Role == ServerRoles.Entry && x.TargetExitId != null).ExecuteUpdateAsync(u => u.SetProperty(x => x.TargetExitId, s.Id));
            }
            if (s.Role == ServerRoles.Entry)
            {
                if (body.ClearTarget == true) s.TargetExitId = null;
                else if (body.TargetExitId is Guid t)
                {
                    var target = await db.Servers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == t && x.Role == ServerRoles.Exit, http.RequestAborted);
                    if (target == null) return Results.BadRequest(new { error = "Нет такого выхода" });
                    if (await ProvisioningGuards.HostExistsAsync(db, target.Host, target.Id, http.RequestAborted))
                        return Results.Conflict(new { error = "Адрес выхода зарегистрирован несколько раз; проверьте существующие записи сервера." });
                    if (target.ProvisioningStatus != null)
                    {
                        var identity = await db.Cluster.AsNoTracking().FirstOrDefaultAsync(c => c.Id == 1, http.RequestAborted);
                        if (!ProvisioningGuards.IsReady(target, identity, DateTime.UtcNow))
                            return Results.Conflict(new { error = "Выход не имеет свежего подтверждения identity, текущей ревизии и работы AWG/Xray." });
                    }
                    s.TargetExitId = t;
                }
            }
            Audit(db, http, "server.update", s.Name);
            await db.SaveChangesAsync();
            await tx.CommitAsync(http.RequestAborted);
            await cluster.BumpAsync();
            return Results.Ok(ServerView(s));
        });

        admin.MapDelete("/servers/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var s = await db.Servers.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound();
            if (await db.ExitEndpoints.AnyAsync(e => e.ServerId == id)) return Results.Conflict(new { error = "Сначала отключите и безопасно перенесите VLESS endpoint и его занятые слоты" });
            await db.Servers.Where(x => x.TargetExitId == s.Id).ExecuteUpdateAsync(u => u.SetProperty(x => x.TargetExitId, (Guid?)null));
            db.Servers.Remove(s);
            Audit(db, http, "server.delete", s.Name);
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        // ───── Общие настройки ─────
        g.MapGet("/cluster", async (ClusterService cluster, HttpContext http) =>
        {
            var c = await cluster.GetAsync(http.RequestAborted);
            if (c == null) return Results.Ok(new { ready = false });
            var awg = ClusterService.AwgOf(c);
            var xray = ClusterService.XrayOf(c);
            return Results.Ok(new
            {
                ready = true,
                c.Title,
                c.PublicHost,
                effectiveHost = await cluster.PublicHostAsync(c, http.RequestAborted),
                accessHost = await cluster.AccessHostAsync(c, http.RequestAborted),
                c.Dns1,
                c.Dns2,
                c.Revision,
                awg = new { awg.Port, protocol = awg.Parameters.ProtocolVersionString, subnet = $"{awg.SubnetAddress}/{awg.SubnetCidr}" },
                xray = xray == null ? null : new
                {
                    xray.Port, xray.Sni, xray.Title,
                    serverFingerprint = xray.Fingerprint,
                    clientFingerprint = c.XrayClientFingerprint,
                    effectiveFingerprint = ClusterService.EffectiveClientFingerprint(c),
                    defaultFingerprint = ClusterService.DefaultClientFingerprint,
                    fingerprints = ClusterService.ClientFingerprints,
                },
            });
        });

        admin.MapPatch("/cluster", async (ClusterPatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var c = await cluster.GetAsync(http.RequestAborted);
            if (c == null) return Results.BadRequest(new { error = "Сначала подключите выход" });
            if (body.XrayClientFingerprint is { } fp)
            {
                fp = fp.Trim().ToLowerInvariant();
                if (fp.Length > 0 && !ClusterService.IsClientFingerprint(fp))
                    return Results.BadRequest(new { error = "Недопустимый отпечаток Xray: " + string.Join(", ", ClusterService.ClientFingerprints) });
                // Не входит в identity выхода и не меняет серверы: ревизию не поднимаем, подтверждение выходов не трогаем.
                c.XrayClientFingerprint = fp.Length == 0 ? null : fp;
                Audit(db, http, "cluster.xray_fingerprint", fp.Length == 0 ? "(по умолчанию " + ClusterService.DefaultClientFingerprint + ")" : fp);
            }
            var serverFields = body.PublicHost != null || body.Dns1 != null || body.Dns2 != null || body.Title != null;
            if (body.PublicHost != null) c.PublicHost = body.PublicHost.Trim();
            if (body.Dns1 != null) c.Dns1 = body.Dns1.Trim();
            if (body.Dns2 != null) c.Dns2 = body.Dns2.Trim();
            if (body.Title != null) c.Title = body.Title.Trim();
            if (serverFields)
            {
                c.Revision++;
                Audit(db, http, "cluster.update", $"{c.PublicHost} {c.Dns1}");
            }
            await db.SaveChangesAsync();
            // Разбудить длинный опрос агентов: они быстрее подтвердят новую ревизию, окно «выход не готов» короче.
            if (serverFields) ClusterService.Changes.Signal();
            return Results.Ok(new { c.Revision });
        });

        // Что вшить в приложение Маяк при сборке: адрес шлюза и открытый ключ.
        admin.MapGet("/gateway", (Mayak.Api.Gateway.GatewayKeys keys) => Results.Ok(new
        {
            ready = keys.Rsa != null,
            endpoint = publicUrl + Mayak.Api.Gateway.GatewayEndpoints.Prefix,
            publicKey = keys.PublicPem,
            keyPath = keys.Path,
        }));

        admin.MapGet("/audit", async (MayakDb db) =>
            Results.Ok(await db.Audit.OrderByDescending(a => a.Id).Take(200).ToListAsync()));
    }

    public static string InstallCommand(string installUrl, string publicUrl, string token) =>
        $"curl -fsSL {installUrl} | bash -s -- --api {publicUrl} --token {token}";

    public static object ServerView(Server s) => new
    {
        s.Id,
        s.Name,
        s.Role,
        s.Host,
        s.City,
        s.Country,
        s.CountryCode,
        s.Fact,
        s.PhotoUrl,
        s.Active,
        s.TargetExitId,
        s.LastSeen,
        online = s.LastSeen > DateTime.UtcNow.AddMinutes(-2),
        s.AgentVersion,
        s.LastError,
        s.ProvisioningStatus,
        s.ProvisioningMessage,
        s.ProvisioningUpdatedAt,
        s.TrustedHostFingerprint,
        s.ProvisionIdentityMatched,
        s.AutoSelectEnabled,
        s.NativeCapacity,
        expectedEgressIps = SafeExpectedIps(s.ExpectedEgressIpsJson),
        report = ReadReport(s.LastReport),
    };

    private static string[] SafeExpectedIps(string json) => AwgAdmissionService.TryExpectedIps(json, out var ips) ? ips : Array.Empty<string>();

    private static object? ReadReport(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            var r = System.Text.Json.JsonSerializer.Deserialize<Mayak.Core.Agent.AgentReport>(json);
            return r == null ? null : new { r.DryRun, r.Warnings, r.Result, r.AppliedRevision, r.At };
        }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static void Audit(MayakDb db, HttpContext http, string action, string details) =>
        db.Audit.Add(new AuditEntry { ActorId = http.Me().Id, Action = action, Details = details });

    private static bool ValidEndpoint(string host, int port, string publicKey, string sni, string shortId, string? flow, string? transport, int capacity, string? xhttpPath, string? xhttpMode) =>
        !string.IsNullOrWhiteSpace(host) && !host.Contains('/') && !host.Contains(' ') && port is > 0 and <= 65535 &&
        !string.IsNullOrWhiteSpace(publicKey) && !publicKey.Contains(' ') && !string.IsNullOrWhiteSpace(sni) &&
        !string.IsNullOrWhiteSpace(shortId) && shortId.Length <= 32 && shortId.All(Uri.IsHexDigit) &&
        (!string.IsNullOrWhiteSpace(transport) && transport is "tcp" or "xhttp") &&
        (transport == "tcp" ? string.IsNullOrWhiteSpace(flow) || flow == "xtls-rprx-vision" : string.IsNullOrWhiteSpace(flow)) &&
        (transport != "xhttp" || !string.IsNullOrWhiteSpace(xhttpPath) && xhttpPath.StartsWith('/') && !xhttpPath.Contains('?') && (string.IsNullOrWhiteSpace(xhttpMode) || xhttpMode is "auto" or "packet-up" or "stream-up")) &&
        capacity > 0;
}
