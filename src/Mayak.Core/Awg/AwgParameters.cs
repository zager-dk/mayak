using System.Security.Cryptography;

namespace Mayak.Core.Awg;

/// <summary>Версия протокола AmneziaWG, которую генерирует сервер.</summary>
public enum AwgProtocolVersion
{
    /// <summary>AWG 2.0 — работает в большинстве актуальных приложений AmneziaVPN и AmneziaWG.</summary>
    V2,
    /// <summary>AWG 3.1 — защита заголовков и случайные тайминги, нужны самые свежие клиенты.</summary>
    V3,
}

/// <summary>
/// Параметры маскировки AmneziaWG. Имена ключей совпадают с файлами awg0.conf
/// и с JSON внутри ключа vpn:// (Jc, Jmin, S1, H1, I1, HeaderProtectionKey…).
/// Логика генерации повторяет AmneziaVPN 4.8.x (AWG 2.0) и 5.1.x (AWG 3.1).
/// </summary>
public sealed class AwgParameters
{
    public const string DefaultSpecialJunk1 =
        "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>";

    // Размеры служебных сообщений WireGuard (для проверки уникальности S1–S3).
    private const int MessageInitiationSize = 148;
    private const int MessageResponseSize = 92;
    private const int MessageCookieReplySize = 64;

    public string Jc { get; set; } = "";
    public string Jmin { get; set; } = "";
    public string Jmax { get; set; } = "";
    public string S1 { get; set; } = "";
    public string S2 { get; set; } = "";
    public string S3 { get; set; } = "";
    public string S4 { get; set; } = "";
    public string H1 { get; set; } = "";
    public string H2 { get; set; } = "";
    public string H3 { get; set; } = "";
    public string H4 { get; set; } = "";
    public string I1 { get; set; } = "";
    public string I2 { get; set; } = "";
    public string I3 { get; set; } = "";
    public string I4 { get; set; } = "";
    public string I5 { get; set; } = "";

    // AWG 3.x
    public string HeaderProtectionKey { get; set; } = "";
    public string ContentPaddingAddition { get; set; } = "";
    public string RekeyAfterTime { get; set; } = "";
    public string RekeyTimeout { get; set; } = "";
    public string RejectAfterTime { get; set; } = "";
    public string KeepaliveTimeout { get; set; } = "";
    public string MaxHandshakeAttempts { get; set; } = "";
    public string RandomTrailers { get; set; } = "";
    public string DisableCookies { get; set; } = "";

    /// <summary>"2" или "3.1" — как поле protocol_version у Amnezia.</summary>
    public string ProtocolVersionString => DetectVersion();

    public bool IsV3 => !string.IsNullOrWhiteSpace(HeaderProtectionKey);

    /// <summary>PersistentKeepalive для клиента: в AWG 3 допускается диапазон.</summary>
    public string PersistentKeepalive => IsV3 ? "25-35" : "25";

    public static AwgParameters Generate(AwgProtocolVersion version) =>
        version == AwgProtocolVersion.V3 ? GenerateV3() : GenerateV2();

    /// <summary>AWG 2.0: случайные S1–S4 и непересекающиеся диапазоны H1–H4.</summary>
    public static AwgParameters GenerateV2()
    {
        int s1 = Rnd(15, 150);
        int s2 = Rnd(15, 150);
        int s3 = Rnd(1, 64);
        int s4 = Rnd(1, 20);

        var used = new HashSet<int> { s1 };
        while (used.Contains(s2) || s1 + MessageInitiationSize == s2 + MessageResponseSize)
            s2 = Rnd(15, 150);
        used.Add(s2);

        while (used.Contains(s3)
               || s1 + MessageInitiationSize == s3 + MessageCookieReplySize
               || s2 + MessageResponseSize == s3 + MessageCookieReplySize)
            s3 = Rnd(1, 64);
        used.Add(s3);

        while (used.Contains(s4))
            s4 = Rnd(1, 20);

        // Четыре непересекающихся возрастающих диапазона в [5, int.MaxValue).
        // В отличие от Amnezia делим пространство на четверти, чтобы последние
        // диапазоны не схлопывались в крошечные.
        var headers = new string[4];
        long quarter = (int.MaxValue - 5L) / 4;
        for (int i = 0; i < 4; i++)
        {
            long lo = 5 + quarter * i;
            long hi = lo + quarter - 1;
            long first = RndLong(lo, hi - 1000);
            long second = RndLong(first + 1, hi);
            headers[i] = $"{first}-{second}";
        }

        return new AwgParameters
        {
            Jc = Rnd(4, 7).ToString(),
            Jmin = "10",
            Jmax = "50",
            S1 = s1.ToString(),
            S2 = s2.ToString(),
            S3 = s3.ToString(),
            S4 = s4.ToString(),
            H1 = headers[0],
            H2 = headers[1],
            H3 = headers[2],
            H4 = headers[3],
            I1 = DefaultSpecialJunk1,
        };
    }

    /// <summary>AWG 3.1: как AmneziaVPN 5.1 (защита заголовков, случайные тайминги).</summary>
    public static AwgParameters GenerateV3() => new()
    {
        Jc = Rnd(4, 7).ToString(),
        Jmin = "10",
        Jmax = "50",
        S1 = "12",
        S2 = "12",
        S3 = "12",
        S4 = "12",
        H1 = "1",
        H2 = "2",
        H3 = "3",
        H4 = "4",
        I1 = DefaultSpecialJunk1,
        HeaderProtectionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        RekeyAfterTime = "100-120",
        RekeyTimeout = "3-7",
        RejectAfterTime = "150-180",
        KeepaliveTimeout = "5-15",
        MaxHandshakeAttempts = "15-20",
        RandomTrailers = "on",
        DisableCookies = "on",
    };

    /// <summary>Строки секции [Interface] серверного awg0.conf (I1–I5 закомментированы, как у Amnezia).</summary>
    public IEnumerable<string> ServerInterfaceLines()
    {
        foreach (var (k, v) in CoreLines())
            yield return $"{k} = {v}";
        foreach (var (k, v) in V3Lines())
            yield return $"{k} = {v}";
        foreach (var (k, v) in SpecialJunkLines(includeEmpty: false))
            yield return $"# {k} = {v}";
    }

    /// <summary>Строки секции [Interface] клиентского конфига (порядок как в template.conf Amnezia).</summary>
    public IEnumerable<string> ClientInterfaceLines()
    {
        foreach (var (k, v) in CoreLines())
            yield return $"{k} = {v}";
        foreach (var (k, v) in SpecialJunkLines(includeEmpty: false))
            yield return $"{k} = {v}";
        foreach (var (k, v) in V3Lines())
            yield return $"{k} = {v}";
    }

    /// <summary>Все параметры для JSON ключа vpn:// (пустые значения пропускаются, I1–I5 всегда есть).</summary>
    public IEnumerable<(string Key, string Value)> JsonPairs()
    {
        foreach (var p in CoreLines()) yield return p;
        foreach (var p in SpecialJunkLines(includeEmpty: true)) yield return p;
        foreach (var p in V3Lines()) yield return p;
    }

    private IEnumerable<(string, string)> CoreLines()
    {
        var pairs = new (string, string)[]
        {
            ("Jc", Jc), ("Jmin", Jmin), ("Jmax", Jmax),
            ("S1", S1), ("S2", S2), ("S3", S3), ("S4", S4),
            ("H1", H1), ("H2", H2), ("H3", H3), ("H4", H4),
        };
        return pairs.Where(p => !string.IsNullOrWhiteSpace(p.Item2));
    }

    private IEnumerable<(string, string)> SpecialJunkLines(bool includeEmpty)
    {
        var pairs = new (string, string)[] { ("I1", I1), ("I2", I2), ("I3", I3), ("I4", I4), ("I5", I5) };
        return includeEmpty ? pairs : pairs.Where(p => !string.IsNullOrWhiteSpace(p.Item2));
    }

    private IEnumerable<(string, string)> V3Lines()
    {
        var pairs = new (string, string)[]
        {
            ("HeaderProtectionKey", HeaderProtectionKey),
            ("ContentPaddingAddition", ContentPaddingAddition),
            ("RekeyAfterTime", RekeyAfterTime),
            ("RekeyTimeout", RekeyTimeout),
            ("RejectAfterTime", RejectAfterTime),
            ("KeepaliveTimeout", KeepaliveTimeout),
            ("MaxHandshakeAttempts", MaxHandshakeAttempts),
            ("RandomTrailers", RandomTrailers),
            ("DisableCookies", DisableCookies),
        };
        return pairs.Where(p => !string.IsNullOrWhiteSpace(p.Item2));
    }

    /// <summary>Читает параметры из секции [Interface] серверного конфига.</summary>
    public static AwgParameters FromServerConfig(AwgConfigFile conf)
    {
        string Get(string key) => conf.GetInterfaceValue(key) ?? "";
        string GetJunk(string key) => conf.GetInterfaceValue(key) ?? conf.GetInterfaceCommentedValue(key) ?? "";

        return new AwgParameters
        {
            Jc = Get("Jc"), Jmin = Get("Jmin"), Jmax = Get("Jmax"),
            S1 = Get("S1"), S2 = Get("S2"), S3 = Get("S3"), S4 = Get("S4"),
            H1 = Get("H1"), H2 = Get("H2"), H3 = Get("H3"), H4 = Get("H4"),
            I1 = GetJunk("I1"), I2 = GetJunk("I2"), I3 = GetJunk("I3"), I4 = GetJunk("I4"), I5 = GetJunk("I5"),
            HeaderProtectionKey = Get("HeaderProtectionKey"),
            ContentPaddingAddition = Get("ContentPaddingAddition"),
            RekeyAfterTime = Get("RekeyAfterTime"),
            RekeyTimeout = Get("RekeyTimeout"),
            RejectAfterTime = Get("RejectAfterTime"),
            KeepaliveTimeout = Get("KeepaliveTimeout"),
            MaxHandshakeAttempts = Get("MaxHandshakeAttempts"),
            RandomTrailers = Get("RandomTrailers"),
            DisableCookies = Get("DisableCookies"),
        };
    }

    private string DetectVersion()
    {
        if (IsV3) return "3.1";
        bool hasJunkSizes = !string.IsNullOrWhiteSpace(S3) || !string.IsNullOrWhiteSpace(S4);
        bool hasRanges = new[] { H1, H2, H3, H4 }.Any(h => h.Contains('-'));
        if (hasJunkSizes || hasRanges) return "2";
        bool hasSpecial = new[] { I1, I2, I3, I4, I5 }.Any(s => !string.IsNullOrWhiteSpace(s));
        return hasSpecial ? "1.5" : "1";
    }

    private static int Rnd(int fromInclusive, int toExclusive) => RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);

    private static long RndLong(long fromInclusive, long toInclusive)
    {
        // Диапазоны умещаются в int, поэтому хватает GetInt32.
        return RandomNumberGenerator.GetInt32((int)fromInclusive, (int)toInclusive + 1);
    }
}
