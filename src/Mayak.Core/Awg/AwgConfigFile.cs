using System.Text;

namespace Mayak.Core.Awg;

/// <summary>
/// Простой редактор серверного awg0.conf: сохраняет текст как есть,
/// умеет читать [Interface], перечислять [Peer], добавлять и удалять пиров.
/// </summary>
public sealed class AwgConfigFile
{
    public sealed class Section
    {
        public string Header { get; set; } = "";
        public List<string> Lines { get; } = new();

        public bool IsPeer => Header.Equals("[Peer]", StringComparison.OrdinalIgnoreCase);
        public bool IsInterface => Header.Equals("[Interface]", StringComparison.OrdinalIgnoreCase);

        public string? Get(string key)
        {
            foreach (var line in Lines)
            {
                var (k, v) = SplitLine(line);
                if (k != null && k.Equals(key, StringComparison.OrdinalIgnoreCase)) return v;
            }
            return null;
        }
    }

    public sealed record Peer(string PublicKey, string? PresharedKey, string AllowedIps)
    {
        /// <summary>IPv4 из AllowedIPs (первый адрес /32).</summary>
        public string? Ip
        {
            get
            {
                foreach (var part in AllowedIps.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    var ip = part.Split('/')[0];
                    if (System.Net.IPAddress.TryParse(ip, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        return ip;
                }
                return null;
            }
        }
    }

    /// <summary>Строки до первой секции (обычно пусто).</summary>
    public List<string> Preamble { get; } = new();
    public List<Section> Sections { get; } = new();

    public static AwgConfigFile Parse(string text)
    {
        var file = new AwgConfigFile();
        Section? current = null;
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.TrimEnd();
            var trimmed = line.Trim();
            if (trimmed.StartsWith('[') && trimmed.EndsWith(']'))
            {
                current = new Section { Header = trimmed };
                file.Sections.Add(current);
                continue;
            }
            if (current == null)
            {
                if (trimmed.Length > 0) file.Preamble.Add(line);
                continue;
            }
            if (trimmed.Length == 0) continue; // пустые строки восстановим при сохранении
            current.Lines.Add(trimmed);
        }
        return file;
    }

    public Section? Interface => Sections.FirstOrDefault(s => s.IsInterface);

    public string? GetInterfaceValue(string key) => Interface?.Get(key);

    /// <summary>Значение закомментированной строки «# I1 = …» (Amnezia хранит так I1–I5 на сервере).</summary>
    public string? GetInterfaceCommentedValue(string key)
    {
        var iface = Interface;
        if (iface == null) return null;
        foreach (var line in iface.Lines)
        {
            if (!line.StartsWith('#')) continue;
            var (k, v) = SplitLine(line.TrimStart('#').Trim());
            if (k != null && k.Equals(key, StringComparison.OrdinalIgnoreCase)) return v;
        }
        return null;
    }

    public IEnumerable<Peer> Peers =>
        Sections.Where(s => s.IsPeer)
                .Select(s => new Peer(s.Get("PublicKey") ?? "", s.Get("PresharedKey"), s.Get("AllowedIPs") ?? ""))
                .Where(p => p.PublicKey.Length > 0);

    public void AddPeer(string publicKey, string presharedKey, string ip)
    {
        var section = new Section { Header = "[Peer]" };
        section.Lines.Add($"PublicKey = {publicKey}");
        section.Lines.Add($"PresharedKey = {presharedKey}");
        section.Lines.Add($"AllowedIPs = {ip}/32");
        Sections.Add(section);
    }

    /// <summary>Удаляет пира по публичному ключу. Возвращает true, если нашёлся.</summary>
    public bool RemovePeer(string publicKey)
    {
        int removed = Sections.RemoveAll(s => s.IsPeer && string.Equals(s.Get("PublicKey"), publicKey, StringComparison.Ordinal));
        return removed > 0;
    }

    public bool HasPeer(string publicKey) => Peers.Any(p => p.PublicKey == publicKey);

    public override string ToString()
    {
        var sb = new StringBuilder();
        foreach (var l in Preamble) sb.Append(l).Append('\n');
        foreach (var s in Sections)
        {
            sb.Append(s.Header).Append('\n');
            foreach (var l in s.Lines) sb.Append(l).Append('\n');
            sb.Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>Разбирает «Key = Value». Значение может содержать «=» (base64, I1).</summary>
    public static (string? Key, string Value) SplitLine(string line)
    {
        if (line.StartsWith('#')) return (null, "");
        int idx = line.IndexOf('=');
        if (idx <= 0) return (null, "");
        return (line[..idx].Trim(), line[(idx + 1)..].Trim());
    }
}
