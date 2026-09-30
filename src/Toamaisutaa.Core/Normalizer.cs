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
}
