using Mayak.Api.Data;
using Mayak.Api.Endpoints;
using Mayak.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace Mayak.Api;

/// <summary>Команды обслуживания из консоли сервера (когда приложения ещё нет или нужно починить права).</summary>
public static class Cli
{
    public static async Task<int> RunAsync(string[] args, MayakDb db, string publicUrl, string agentInstallUrl)
    {
        switch (args[0])
        {
            case "migrate":
                Console.WriteLine("База в актуальном состоянии.");
                return 0;

            case "role" when args.Length == 3:
            {
                var who = args[1].TrimStart('@');
                var acc = long.TryParse(who, out var id)
                    ? await db.Accounts.FirstOrDefaultAsync(a => a.TelegramId == id)
                    : await db.Accounts.FirstOrDefaultAsync(a => a.TelegramUsername != null && a.TelegramUsername.ToLower() == who.ToLower());
                if (acc == null) { Console.Error.WriteLine($"Нет аккаунта {args[1]}: человек должен сначала войти через бота."); return 1; }
                if (!Roles.All.Contains(args[2])) { Console.Error.WriteLine("Роль: user, support, admin или owner"); return 1; }
                acc.Role = args[2];
                acc.Enabled = true;
                db.Audit.Add(new AuditEntry { Action = "cli.role", Details = $"{acc.Name} → {acc.Role}" });
                await db.SaveChangesAsync();
                Console.WriteLine($"{acc.Name}: роль {acc.Role}, доступ включён.");
                return 0;
            }

            case "add-server" when args.Length >= 4:
            {
                var role = args[1];
                if (role is not (ServerRoles.Exit or ServerRoles.Entry)) { Console.Error.WriteLine("Тип сервера: exit или entry"); return 1; }
                var token = Tokens.New();
                var s = new Server
                {
                    Role = role,
                    Name = args[2],
                    Host = args[3],
                    City = args.ElementAtOrDefault(4) ?? "",
                    Country = args.ElementAtOrDefault(5) ?? "",
                    AgentTokenHash = Tokens.Hash(token),
                    Active = role == ServerRoles.Exit && !await db.Servers.AnyAsync(x => x.Role == ServerRoles.Exit),
                };
                db.Servers.Add(s);
                db.Audit.Add(new AuditEntry { Action = "cli.add-server", Details = $"{s.Role} {s.Name} {s.Host}" });
                await db.SaveChangesAsync();
                Console.WriteLine($"Сервер «{s.Name}» добавлен. Выполните на нём:");
                Console.WriteLine();
                Console.WriteLine(AdminEndpoints.InstallCommand(agentInstallUrl, publicUrl, token));
                return 0;
            }

            case "servers":
                foreach (var s in await db.Servers.OrderBy(s => s.Role).ToListAsync())
                    Console.WriteLine($"{s.Role,-6} {s.Name,-24} {s.Host,-18} {(s.Active ? "активный " : "")}{(s.LastSeen == null ? "агент ещё не выходил на связь" : $"связь {s.LastSeen:dd.MM HH:mm} UTC")}{(s.LastError != null ? " · ошибка: " + s.LastError : "")}");
                return 0;

            default:
                Console.Error.WriteLine("Команды: role <@telegram|id> <роль>, add-server <exit|entry> <имя> <адрес> [город] [страна], servers, migrate");
                return 1;
        }
    }
}
