using System.Text.Json;
using Mayak.Core.Models;
using Mayak.Core.Server;

namespace Mayak.Core.Probe;

/// <summary>
/// Всё, что нужно «Проверке» без SSH: параметры AmneziaWG и Xray сервера и проверочная учётка.
/// Маяк сохраняет это на компьютере после каждого удачного подключения, чтобы проверять протоколы
/// из сети, где сервер по SSH недоступен, даже после перезапуска приложения.
/// Ключей пользователей здесь нет.
/// </summary>
public sealed class CheckKit
{
    public ServerEndpoint Endpoint { get; set; } = new();
    public XrayEndpoint? Xray { get; set; }
    public string ServerAddress { get; set; } = "10.8.1.0";
    public string Dns1 { get; set; } = "1.1.1.1";
    public ProbeIdentity Probe { get; set; } = new();
    public DateTime SavedUtc { get; set; }

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    public static CheckKit? From(ServerSnapshot snap)
    {
        if (snap.Db.Probe is not { } p || string.IsNullOrEmpty(p.AwgPrivateKey)) return null;
        return new CheckKit
        {
            Endpoint = snap.Endpoint,
            Xray = snap.Xray,
            ServerAddress = snap.ServerAddress,
            Dns1 = snap.Db.Dns1,
            Probe = p,
            SavedUtc = DateTime.UtcNow,
        };
    }

    /// <summary>Снимок только для проверки: без пользователей и статистики.</summary>
    public ServerSnapshot ToSnapshot() => new()
    {
        Endpoint = Endpoint,
        Xray = Xray,
        ServerAddress = ServerAddress,
        Db = new MayakDatabase { Dns1 = Dns1, Probe = Probe },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Options);

    public static CheckKit? FromJson(string json)
    {
        try { return JsonSerializer.Deserialize<CheckKit>(json, Options); }
        catch (JsonException) { return null; }
    }
}
