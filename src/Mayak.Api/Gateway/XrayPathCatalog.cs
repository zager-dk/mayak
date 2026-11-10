using System.Text.Json;
using System.Text.Json.Nodes;
using Mayak.Api.Data;
using Mayak.Api.Services;
using Mayak.Core.Export;

namespace Mayak.Api.Gateway;

/// <summary>
/// Запасные пути Xray на тот же выход, что выдан допуском AWG (приложение 5.1.0.21+, поле запроса mayak_paths=1).
/// Порядок в приложении: AWG, затем эти пути по очереди. Место на выходе — то же allocation_id, учёт не меняется.
/// Без поля запроса ответ остаётся прежним байт в байт (правило 3).
/// </summary>
public static class XrayPathCatalog
{
    public const int Schema = 1;
    /// <summary>Сколько путей Xray отдавать: вместе с AWG получается 4 пути на один сервер.</summary>
    public const int PathCount = 3;
    private static readonly string[] FallbackOrder = ["safari", "chrome", "random"];

    public static bool IsRequested(JsonObject request)
    {
        if (request["mayak_paths"] is not JsonValue value) return false;
        if (value.TryGetValue<int>(out var integer)) return integer == 1;
        return value.TryGetValue<JsonElement>(out var element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt32(out integer)
            && integer == 1;
    }

    /// <summary>Отпечатки по порядку: выбранный в админке (по умолчанию firefox), затем запасные, без повторов.</summary>
    public static IReadOnlyList<string> Fingerprints(ClusterIdentity c) =>
        new[] { ClusterService.EffectiveClientFingerprint(c) }.Concat(FallbackOrder).Distinct(StringComparer.Ordinal).Take(PathCount).ToArray();

    /// <summary>null — Xray на кластере нет или у устройства нет XrayId.</summary>
    public static JsonObject? Build(ClusterIdentity c, string host, Device device)
    {
        if (string.IsNullOrEmpty(device.XrayId) || string.IsNullOrWhiteSpace(host)) return null;
        var paths = new JsonArray();
        foreach (var fp in Fingerprints(c))
        {
            var xray = ClusterService.XrayOf(c);
            if (xray == null) return null;
            xray.Fingerprint = fp;
            var container = Mayak.Core.Xray.XrayConfig.BuildAmneziaContainer(host, xray, device.XrayId);
            if (xray.Transport == "xhttp") container["xray"]!["xhttp"]!["xhttp_mode"] = xray.XhttpMode;
            var root = new JsonObject
            {
                ["config_version"] = 2, ["name"] = c.Title, ["hostName"] = host,
                ["defaultContainer"] = "amnezia-xray", ["containers"] = new JsonArray(container),
                ["dns1"] = c.Dns1, ["dns2"] = c.Dns2,
            };
            paths.Add(new JsonObject { ["id"] = "xray-" + fp, ["fingerprint"] = fp, ["config"] = VpnKeyCodec.Encode(root.ToJsonString()) });
        }
        return new JsonObject { ["schema"] = Schema, ["paths"] = paths };
    }
}
