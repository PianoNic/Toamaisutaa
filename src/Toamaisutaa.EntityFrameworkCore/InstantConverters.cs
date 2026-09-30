using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Stores instants as Unix milliseconds, because EF Core cannot translate range comparisons on a
/// SQLite <see cref="DateTimeOffset"/> column. A round trip drops the offset and sub-millisecond
/// precision, so do not use these for values where either carries meaning.
/// </summary>
internal static class InstantConverters
{
    internal static readonly ValueConverter<DateTimeOffset, long> Instant = new(
        value => value.ToUniversalTime().ToUnixTimeMilliseconds(),
        value => DateTimeOffset.FromUnixTimeMilliseconds(value));

    internal static readonly ValueConverter<DateTimeOffset?, long?> NullableInstant = new(
        value => value == null ? null : value.Value.ToUniversalTime().ToUnixTimeMilliseconds(),
        value => value == null ? null : DateTimeOffset.FromUnixTimeMilliseconds(value.Value));
}
