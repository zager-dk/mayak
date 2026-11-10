using System.Text.Json.Nodes;
using Mayak.Api.Gateway;

var failed = 0;
var passed = 0;
void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (ok) passed++; else failed++;
}

var selectedId = Guid.Parse("ae9705a1-ae64-43cb-a106-8f0161ab48d2");
var differentClusterDefault = Guid.Parse("00000000-0000-0000-0000-000000000001");
var oldResponse = new JsonObject { ["allocation_id"] = "allocation", ["config"] = "encrypted-config" };
ExitLocationCatalog.AddToResponse(oldResponse, new JsonObject(), selectedId, "Осло", "Норвегия", "");
Check("old request shape remains unchanged", oldResponse.Count == 2 && !oldResponse.ContainsKey("exit_location"));

var malformedCapabilities = new[] { "{}", "{\"mayak_exit_location\":0}", "{\"mayak_exit_location\":2}",
    "{\"mayak_exit_location\":\"1\"}", "{\"mayak_exit_location\":true}", "{\"mayak_exit_location\":1.0}",
    "{\"mayak_exit_location\":{}}", "{\"mayak_exit_location\":[]}" };
bool malformedSafe = true;
foreach (var json in malformedCapabilities)
{
    var request = JsonNode.Parse(json)!.AsObject();
    var response = new JsonObject { ["config"] = "unchanged" };
    ExitLocationCatalog.AddToResponse(response, request, selectedId, "Осло", "Норвегия", "NO");
    malformedSafe &= response.Count == 1 && !response.ContainsKey("exit_location");
}
Check("absent, malformed and unsupported opt-ins preserve response", malformedSafe);

var aliases = new (string City, string Country, string Code, string Expected)[]
{
    ("Осло", "Норвегия", "", "oslo"),
    ("Oslo", "Norway", "NO", "oslo"),
    ("Хельсинки", "Finland", "FI", "helsinki"),
    ("Helsinki", "", "FI", "helsinki"),
    ("Амстердам", "Нидерланды", "NL", "amsterdam"),
    ("Amsterdam", "The Netherlands", "", "amsterdam"),
    ("Франкфурт-на-Майне", "Германия", "DE", "frankfurt"),
    ("Frankfurt am Main", "Germany", "", "frankfurt"),
    ("Стокгольм", "Sweden", "SE", "stockholm"),
    ("Stockholm", "Швеция", "", "stockholm"),
};
Check("only exact reviewed city/country/code aliases map", aliases.All(x =>
    ExitLocationCatalog.CityId(x.City, x.Country, x.Code) == x.Expected));

var unknownOrContradictory = new[]
{
    ExitLocationCatalog.CityId("Осло", "Швеция", "NO"),
    ExitLocationCatalog.CityId("Осло", "Норвегия", "SE"),
    ExitLocationCatalog.CityId("Осло", "Норвегия", "ZZ"),
    ExitLocationCatalog.CityId("Неизвестный город", "Норвегия", "NO"),
    ExitLocationCatalog.CityId("Осло", "Неизвестная страна", ""),
    ExitLocationCatalog.CityId("Осло", "", ""),
};
Check("contradictory and unknown metadata remains unknown", unknownOrContradictory.All(x => x.Length == 0));
var unknownCityResponse = new JsonObject();
ExitLocationCatalog.AddToResponse(unknownCityResponse, JsonNode.Parse("{\"mayak_exit_location\":1}")!.AsObject(),
    selectedId, "Осло", "Unknown", "");
Check("unknown city keeps candidate id but exposes no guessed city",
    unknownCityResponse["exit_location"]?["candidate_id"]?.GetValue<string>() == selectedId.ToString("D")
    && unknownCityResponse["exit_location"]?["city_id"]?.GetValue<string>() == "");

var optInRequest = JsonNode.Parse("{\"mayak_exit_location\":1}")!.AsObject();
var optInResponse = new JsonObject { ["allocation_id"] = "allocation", ["config"] = "encrypted-config" };
ExitLocationCatalog.AddToResponse(optInResponse, optInRequest, selectedId, "Осло", "Норвегия", "");
var location = optInResponse["exit_location"]!.AsObject();
Check("opt-in identifies the selected allocation server, not cluster default",
    selectedId != differentClusterDefault && location.Count == 3
    && location["schema"]?.GetValue<int>() == 1
    && location["candidate_id"]?.GetValue<string>() == selectedId.ToString("D")
    && location["city_id"]?.GetValue<string>() == "oslo");
Check("location object contains only the allowlisted fields",
    location.Select(property => property.Key).ToHashSet(StringComparer.Ordinal)
        .SetEquals(new[] { "schema", "candidate_id", "city_id" }));

Console.WriteLine($"Summary: {passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
