namespace Toamaisutaa.Core;

/// <summary>
/// The PHC string format: <c>$algorithm$param=value,param=value$salt$hash</c>, base64 without
/// padding. Storing the algorithm and its parameters in the row is what turns an iteration-count
/// increase, or a move to a different algorithm entirely, into a rehash on next login rather than a
/// migration.
/// </summary>
internal sealed record PhcString(string Algorithm, IReadOnlyDictionary<string, string> Parameters, byte[] Salt, byte[] Hash)
{
    /// <summary>Refuses anything it does not fully understand, so a malformed or truncated row
    /// fails closed rather than throwing out of a login.</summary>
    internal static bool TryParse(string? value, out PhcString result)
    {
        result = null!;

        if (string.IsNullOrEmpty(value) || value[0] != '$')
            return false;

        var segments = value.Split('$');
        if (segments.Length != 5 || segments[0].Length != 0)
            return false;

        var algorithm = segments[1];
        if (algorithm.Length == 0)
            return false;

        if (!TryParseParameters(segments[2], out var parameters))
            return false;

        if (!TryDecode(segments[3], out var salt) || !TryDecode(segments[4], out var hash))
            return false;

        if (salt.Length == 0 || hash.Length == 0)
            return false;

        result = new PhcString(algorithm, parameters, salt, hash);
        return true;
    }

    internal static string Format(string algorithm, IEnumerable<KeyValuePair<string, string>> parameters, byte[] salt, byte[] hash) =>
        $"${algorithm}${string.Join(',', parameters.Select(parameter => $"{parameter.Key}={parameter.Value}"))}${Encode(salt)}${Encode(hash)}";

    internal bool TryGetInt32(string name, out int value)
    {
        value = 0;
        return Parameters.TryGetValue(name, out var raw) && int.TryParse(raw, out value);
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
