using Mayak.Api.Data;
using Mayak.Api.Services;
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
    bool? Active, Guid? TargetExitId, bool? ClearTarget);
public sealed record ClusterPatch(string? PublicHost, string? Dns1, string? Dns2, string? Title);

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

        g.MapPatch("/accounts/{id:guid}", async (Guid id, AccountPatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            var me = http.Me();
            if (body.Role != null)
            {
                if (me.Role != Roles.Owner) return Results.Json(new { error = "Роли назначает только владелец" }, statusCode: 403);
                if (!Roles.All.Contains(body.Role)) return Results.BadRequest(new { error = "Неизвестная роль" });
                acc.Role = body.Role;
            }
            if (body.Name != null) acc.Name = body.Name.Trim();
            if (body.Note != null) acc.Note = body.Note.Trim();
            if (body.Enabled != null) acc.Enabled = body.Enabled.Value;
            if (body.ClearPaidUntil == true) acc.PaidUntil = null;
            else if (body.PaidUntil != null) acc.PaidUntil = body.PaidUntil.Value.ToUniversalTime();
            if (body.MaxDevices != null) acc.MaxDevices = Math.Max(0, body.MaxDevices.Value);
            if (body.DownMbps != null) acc.DownMbps = Math.Max(0, body.DownMbps.Value);
            if (body.UpMbps != null) acc.UpMbps = Math.Max(0, body.UpMbps.Value);
            Audit(db, http, "account.update", $"{acc.Id} {acc.Name}");
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.Ok(AppEndpoints.AccountView(acc));
        });

        admin.MapDelete("/accounts/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var acc = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id);
            if (acc == null) return Results.NotFound();
            if (acc.Role == Roles.Owner) return Results.BadRequest(new { error = "Владельца удалить нельзя" });
            db.Accounts.Remove(acc);
            Audit(db, http, "account.delete", $"{acc.Id} {acc.Name}");
            await db.SaveChangesAsync();
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
                var (key, conf) = await cluster.BuildFilesAsync(d, d.Account, http.RequestAborted);
                return Results.Ok(new { vpnKey = key, conf });
            }
            catch (InvalidOperationException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        g.MapPatch("/devices/{id:guid}", async (Guid id, DevicePatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id);
            if (d == null) return Results.NotFound();
            if (body.Name != null) d.Name = body.Name.Trim();
            if (body.Enabled != null) d.Enabled = body.Enabled.Value;
            if (body.ClearLimits == true) { d.DownMbps = null; d.UpMbps = null; }
            if (body.DownMbps != null) d.DownMbps = Math.Max(0, body.DownMbps.Value);
            if (body.UpMbps != null) d.UpMbps = Math.Max(0, body.UpMbps.Value);
            Audit(db, http, "device.update", $"{d.Id} {d.Name}");
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.Ok(AppEndpoints.DeviceView(d));
        });

        g.MapDelete("/devices/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var d = await db.Devices.FirstOrDefaultAsync(x => x.Id == id);
            if (d == null) return Results.NotFound();
            db.Devices.Remove(d);
            Audit(db, http, "device.delete", $"{d.Id} {d.Name}");
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.NoContent();
        });

        // ───── Серверы ─────
        g.MapGet("/servers", async (MayakDb db) =>
            Results.Ok((await db.Servers.OrderBy(s => s.Role).ThenBy(s => s.Name).ToListAsync()).Select(ServerView)));

        admin.MapPost("/servers", async (ServerCreate body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            if (body.Role is not (ServerRoles.Exit or ServerRoles.Entry)) return Results.BadRequest(new { error = "role: exit или entry" });
            if (string.IsNullOrWhiteSpace(body.Host)) return Results.BadRequest(new { error = "Нужен адрес сервера" });
            var token = Tokens.New();
            var s = new Server
            {
                Name = string.IsNullOrWhiteSpace(body.Name) ? body.Host.Trim() : body.Name.Trim(),
                Role = body.Role,
                Host = body.Host.Trim(),
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
            var s = await db.Servers.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound();
            if (body.Name != null) s.Name = body.Name.Trim();
            if (body.Host != null) s.Host = body.Host.Trim();
            if (body.City != null) s.City = body.City.Trim();
            if (body.Country != null) s.Country = body.Country.Trim();
            if (body.CountryCode != null) s.CountryCode = body.CountryCode.Trim().ToLowerInvariant();
            if (body.Fact != null) s.Fact = body.Fact.Trim();
            if (body.PhotoUrl != null) s.PhotoUrl = body.PhotoUrl.Length == 0 ? null : body.PhotoUrl;
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
                    if (!await db.Servers.AnyAsync(x => x.Id == t && x.Role == ServerRoles.Exit)) return Results.BadRequest(new { error = "Нет такого выхода" });
                    s.TargetExitId = t;
                }
            }
            Audit(db, http, "server.update", s.Name);
            await db.SaveChangesAsync();
            await cluster.BumpAsync();
            return Results.Ok(ServerView(s));
        });

        admin.MapDelete("/servers/{id:guid}", async (Guid id, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var s = await db.Servers.FirstOrDefaultAsync(x => x.Id == id);
            if (s == null) return Results.NotFound();
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
                c.Dns1,
                c.Dns2,
                c.Revision,
                awg = new { awg.Port, protocol = awg.Parameters.ProtocolVersionString, subnet = $"{awg.SubnetAddress}/{awg.SubnetCidr}" },
                xray = xray == null ? null : new { xray.Port, xray.Sni, xray.Title },
            });
        });

        admin.MapPatch("/cluster", async (ClusterPatch body, HttpContext http, MayakDb db, ClusterService cluster) =>
        {
            var c = await cluster.GetAsync(http.RequestAborted);
            if (c == null) return Results.BadRequest(new { error = "Сначала подключите выход" });
            if (body.PublicHost != null) c.PublicHost = body.PublicHost.Trim();
            if (body.Dns1 != null) c.Dns1 = body.Dns1.Trim();
            if (body.Dns2 != null) c.Dns2 = body.Dns2.Trim();
            if (body.Title != null) c.Title = body.Title.Trim();
            c.Revision++;
            Audit(db, http, "cluster.update", $"{c.PublicHost} {c.Dns1}");
            await db.SaveChangesAsync();
            return Results.Ok(new { c.Revision });
        });

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
        report = ReadReport(s.LastReport),
    };

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
}
