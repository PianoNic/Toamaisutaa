using System.Text.Json;

namespace Toamaisutaa.Core;

/// <summary>
/// Turns a userinfo response into claims. Lives here rather than next to the HTTP call because it
/// is pure text in, claims out, and that is the part worth testing.
/// </summary>
internal static class ClaimsJsonFlattener
{
    /// <summary>
    /// Scalars become one claim. Arrays become one claim per entry, which is the only shape a
    /// groups array can arrive in if a role check is to match any single group inside it. Nested
    /// objects, and objects inside arrays, are skipped: a claim value is a string, and flattening
    /// an object into one would invent a format nothing agrees on.
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
