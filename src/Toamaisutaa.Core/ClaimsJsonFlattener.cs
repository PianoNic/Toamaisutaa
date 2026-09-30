using System.Text.Json;

namespace Toamaisutaa.Core;

internal static class ClaimsJsonFlattener
{
    /// <summary>
    /// Arrays become one claim per entry so a role check can match any single group; nested objects
    /// are skipped because flattening one into a string would invent a format nothing agrees on.
    /// </summary>
    internal static IReadOnlyList<(string Type, string Value)> Parse(string json)
    {
        using var document = JsonDocument.Parse(json);

        if (document.RootElement.ValueKind != JsonValueKind.Object)
            return [];

        var claims = new List<(string, string)>();

        foreach (var property in document.RootElement.EnumerateObject())
        {
            switch (property.Value.ValueKind)
            {
                case JsonValueKind.String:
                    Add(property.Name, property.Value.GetString());
                    break;

                case JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False:
                    Add(property.Name, property.Value.ToString());
                    break;

                case JsonValueKind.Array:
                    foreach (var entry in property.Value.EnumerateArray())
                    {
                        switch (entry.ValueKind)
                        {
                            case JsonValueKind.String:
                                Add(property.Name, entry.GetString());
                                break;

                            case JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False:
                                Add(property.Name, entry.ToString());
                                break;
                        }
                    }

                    break;
            }
        }

        return claims;

        void Add(string type, string? value)
        {
            if (!string.IsNullOrEmpty(value))
                claims.Add((type, value));
        }
    }
}
