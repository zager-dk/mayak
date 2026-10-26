namespace MayakVPN.Views;

/// <summary>Сайты, под которые обычно маскируют Reality: TLS 1.3, HTTP/2, не заблокированы в России.</summary>
public static class XraySites
{
    public static IReadOnlyList<string> Suggestions { get; } = new[]
    {
        "www.googletagmanager.com",
        "www.microsoft.com",
        "dl.google.com",
        "www.samsung.com",
        "www.apple.com",
        "www.cloudflare.com",
    };

    public static bool IsValidHost(string host) =>
        host.Length is > 3 and < 254 && host.Contains('.') && !host.Contains(' ') && !host.Contains('/') &&
        Uri.CheckHostName(host) == UriHostNameType.Dns;
}
