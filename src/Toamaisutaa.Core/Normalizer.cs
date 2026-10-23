namespace Toamaisutaa.Core;

/// <summary>
/// Normalised here rather than by the database, so identifier equality does not depend on the
/// provider's collation.
/// </summary>
internal static class Normalizer
{
    internal static string Normalize(string value) => value.Trim().ToUpperInvariant();

    internal static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Normalize(value);

    /// <summary>
    /// False for a value whose upper-casing turns one of its letters into another: U+017F, the long s,
    /// becomes S, so "ſam@x.com" and "sam@x.com" are different mailboxes with one normalised form,
    /// and the first could hold the second's identifier.
    /// </summary>
    internal static bool FoldsCleanly(string value)
    {
        var trimmed = value.Trim();
        return string.Equals(Normalize(trimmed).ToLowerInvariant(), trimmed.ToLowerInvariant(), StringComparison.Ordinal);
    }
}
