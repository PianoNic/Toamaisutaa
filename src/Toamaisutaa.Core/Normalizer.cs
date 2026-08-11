namespace Toamaisutaa.Core;

/// <summary>
/// Login identifiers are normalised here rather than left to the database, so that whether
/// <c>Nic@Example.com</c> and <c>nic@example.com</c> are the same account does not depend on which
/// provider the deployment happens to use or how its collation was configured.
/// </summary>
internal static class Normalizer
{
    internal static string Normalize(string value) => value.Trim().ToUpperInvariant();

    internal static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Normalize(value);
}
