using System.Reflection;

namespace Mayak.Core.Server;

/// <summary>Серверные скрипты, вшитые в сборку. Подстановка переменных {{NAME}}.</summary>
public static class ScriptLibrary
{
    public static string Load(string name, IReadOnlyDictionary<string, string>? vars = null)
    {
        var asm = typeof(ScriptLibrary).Assembly;
        using var stream = asm.GetManifestResourceStream("Mayak.Scripts." + name)
                           ?? throw new InvalidOperationException($"Скрипт {name} не найден в сборке");
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd().Replace("\r\n", "\n");
        if (vars != null)
        {
            foreach (var (k, v) in vars)
                text = text.Replace("{{" + k + "}}", v);
        }
        return text;
    }
}
