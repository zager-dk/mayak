using System.Text;

namespace Mayak.Core.Export;

public static class Transliteration
{
    private static readonly Dictionary<char, string> Map = new()
    {
        ['а'] = "a", ['б'] = "b", ['в'] = "v", ['г'] = "g", ['д'] = "d", ['е'] = "e", ['ё'] = "e",
        ['ж'] = "zh", ['з'] = "z", ['и'] = "i", ['й'] = "y", ['к'] = "k", ['л'] = "l", ['м'] = "m",
        ['н'] = "n", ['о'] = "o", ['п'] = "p", ['р'] = "r", ['с'] = "s", ['т'] = "t", ['у'] = "u",
        ['ф'] = "f", ['х'] = "h", ['ц'] = "ts", ['ч'] = "ch", ['ш'] = "sh", ['щ'] = "sch", ['ъ'] = "",
        ['ы'] = "y", ['ь'] = "", ['э'] = "e", ['ю'] = "yu", ['я'] = "ya",
    };

    /// <summary>Латиница: буквы, цифры, «-» и «_».</summary>
    public static string ToLatin(string text)
    {
        var sb = new StringBuilder();
        foreach (var ch in text.ToLowerInvariant())
        {
            if (Map.TryGetValue(ch, out var rep)) sb.Append(rep);
            else if (ch is >= 'a' and <= 'z' or >= '0' and <= '9') sb.Append(ch);
            else if (ch is '-' or '_' or ' ' or '.') sb.Append('-');
        }
        var s = sb.ToString();
        while (s.Contains("--")) s = s.Replace("--", "-");
        return s.Trim('-');
    }

    /// <summary>Имя туннеля WireGuard: [a-zA-Z0-9_=+.-], не длиннее 15 символов.</summary>
    public static string ToTunnelName(string text)
    {
        var s = ToLatin(text);
        if (s.Length == 0) s = "mayak";
        if (s.Length > 15) s = s[..15].TrimEnd('-');
        return s;
    }
}
