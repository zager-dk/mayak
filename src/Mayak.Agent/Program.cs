using System.Text.Json;
using Mayak.Agent;

// Агент Маяка: mayak-agent [путь к конфигу, по умолчанию /etc/mayak/agent.json]
//              mayak-agent --once  — один проход и выход (проверка после установки)
var path = args.FirstOrDefault(a => !a.StartsWith("--")) ?? "/etc/mayak/agent.json";
if (!File.Exists(path))
{
    Console.Error.WriteLine($"Нет файла настроек {path}. Установите агента командой из админки Маяка.");
    return 2;
}
var cfg = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
          ?? throw new InvalidOperationException("Пустой файл настроек");
if (string.IsNullOrWhiteSpace(cfg.Api) || string.IsNullOrWhiteSpace(cfg.Token))
{
    Console.Error.WriteLine("В настройках нет api или token.");
    return 2;
}

var runner = new AgentRunner(cfg);
if (args.Contains("--once"))
{
    try
    {
        await runner.CycleAsync(CancellationToken.None);
        Console.WriteLine($"Готово: агент на связи с API как «{runner.Role}».");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("Ошибка: " + ex.Message);
        return 1;
    }
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();
await runner.RunAsync(cts.Token);
return 0;
