namespace Toamaisutaa.Core;

/// <summary>
/// The version is its own segment rather than a parameter because Argon2's canonical encoding
/// (<c>$argon2id$v=19$m=19456,t=2,p=1$...</c>) puts it there, and other Argon2 implementations
/// must be able to read our rows.
/// </summary>
internal sealed record PhcString(
    string Algorithm,
    IReadOnlyDictionary<string, string> Parameters,
    byte[] Salt,
    byte[] Hash,
    int? Version = null)
{
    /// <summary>Refuses anything it does not fully understand, so a malformed row fails closed
    /// rather than throwing out of a login.</summary>
    internal static bool TryParse(string? value, out PhcString result)
    {
        result = null!;

        if (string.IsNullOrEmpty(value) || value[0] != '$')
            return false;

        var segments = value.Split('$');
        if (segments.Length is not (5 or 6) || segments[0].Length != 0)
            return false;

        var algorithm = segments[1];
        if (algorithm.Length == 0)
            return false;

        var versioned = segments.Length == 6;
        int? version = null;

        if (versioned)
        {
            if (!TryParseVersion(segments[2], out var parsedVersion))
                return false;

            version = parsedVersion;
        }

        var offset = versioned ? 3 : 2;

        if (!TryParseParameters(segments[offset], out var parameters))
            return false;

        if (!TryDecode(segments[offset + 1], out var salt) || !TryDecode(segments[offset + 2], out var hash))
            return false;

        if (salt.Length == 0 || hash.Length == 0)
            return false;

        result = new PhcString(algorithm, parameters, salt, hash, version);
        return true;
    }

    internal static string Format(string algorithm, IEnumerable<KeyValuePair<string, string>> parameters, byte[] salt, byte[] hash) =>
        Format(algorithm, null, parameters, salt, hash);

    internal static string Format(string algorithm, int? version, IEnumerable<KeyValuePair<string, string>> parameters, byte[] salt, byte[] hash) =>
        $"${algorithm}{(version is null ? string.Empty : $"$v={version}")}$"
        + $"{string.Join(',', parameters.Select(parameter => $"{parameter.Key}={parameter.Value}"))}${Encode(salt)}${Encode(hash)}";

    internal bool TryGetInt32(string name, out int value)
    {
        value = 0;
        return Parameters.TryGetValue(name, out var raw) && int.TryParse(raw, out value);
    }

    private static bool TryParseVersion(string segment, out int version)
    {
        version = 0;

        return segment.StartsWith("v=", StringComparison.Ordinal)
            && int.TryParse(segment[2..], out version)
            && version >= 0;
    }

    private static bool TryParseParameters(string segment, out IReadOnlyDictionary<string, string> parameters)
    {
        var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
        parameters = parsed;

        if (segment.Length == 0)
            return true;

        foreach (var pair in segment.Split(','))
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0 || separator == pair.Length - 1)
                return false;

            parsed[pair[..separator]] = pair[(separator + 1)..];
        }

        return true;
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=');

    private static bool TryDecode(string value, out byte[] decoded)
    {
        decoded = [];

        if (value.Length == 0)
            return false;

        var padded = value + new string('=', (4 - value.Length % 4) % 4);

        try
        {
            decoded = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
