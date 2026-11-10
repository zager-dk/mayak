using System.Text.Json;
using System.Text.Json.Nodes;

namespace Mayak.Api.Gateway;

/// <summary>Exact reviewed presentation aliases for known exit cities. Unknown metadata stays unknown.</summary>
public static class ExitLocationCatalog
{
    private sealed record CityMapping(string Id, string[] Names, string[] Countries, string CountryCode);

    private static readonly CityMapping[] Mappings =
    {
        new("oslo", new[] { "Осло", "Oslo" }, new[] { "Норвегия", "Norway" }, "NO"),
        new("helsinki", new[] { "Хельсинки", "Helsinki" }, new[] { "Финляндия", "Finland" }, "FI"),
        new("amsterdam", new[] { "Амстердам", "Amsterdam" }, new[] { "Нидерланды", "Netherlands", "The Netherlands" }, "NL"),
        new("frankfurt", new[] { "Франкфурт", "Frankfurt", "Frankfurt am Main", "Франкфурт-на-Майне" }, new[] { "Германия", "Germany" }, "DE"),
        new("stockholm", new[] { "Стокгольм", "Stockholm" }, new[] { "Швеция", "Sweden" }, "SE"),
    };

    public static bool IsRequested(JsonObject request)
    {
        if (request["mayak_exit_location"] is not JsonValue value) return false;
        if (value.TryGetValue<int>(out var integer)) return integer == 1;
        return value.TryGetValue<JsonElement>(out var element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetInt32(out integer)
            && integer == 1;
    }

    public static string CityId(string? city, string? country, string? countryCode)
    {
        var cityValue = city?.Trim();
        if (string.IsNullOrEmpty(cityValue)) return "";
        var mapping = Mappings.FirstOrDefault(candidate => candidate.Names.Contains(cityValue, StringComparer.OrdinalIgnoreCase));
        if (mapping == null) return "";

        var countryValue = country?.Trim();
        var countryCodeValue = countryCode?.Trim();
        var hasCountry = !string.IsNullOrEmpty(countryValue);
        var hasCountryCode = !string.IsNullOrEmpty(countryCodeValue);
        if (!hasCountry && !hasCountryCode) return "";
        if (hasCountry && !mapping.Countries.Contains(countryValue!, StringComparer.OrdinalIgnoreCase)) return "";
        if (hasCountryCode && !string.Equals(mapping.CountryCode, countryCodeValue, StringComparison.OrdinalIgnoreCase)) return "";
        return mapping.Id;
    }

    public static void AddToResponse(JsonObject response, JsonObject request, Guid selectedServerId,
        string? city, string? country, string? countryCode)
    {
        if (!IsRequested(request)) return;
        response["exit_location"] = new JsonObject
        {
            ["schema"] = 1,
            ["candidate_id"] = selectedServerId.ToString("D"),
            ["city_id"] = CityId(city, country, countryCode),
        };
    }
}
