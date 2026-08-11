using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Stores instants as Unix milliseconds rather than as a provider-native timestamp.
/// </summary>
/// <remarks>
/// Not a preference. SQLite has no timestamp type, so EF Core keeps a <see cref="DateTimeOffset"/>
/// as text and then refuses to translate <c>&lt;</c> or <c>&gt;</c> on it - correctly, because two
/// instants written with different offsets do not compare in the right order as strings. That makes
/// "delete everything that expired before now" untranslatable on one of the two supported
/// providers.
/// <para>
/// A signed integer sorts identically everywhere, translates on both providers, and is unambiguous
/// about the instant it names. The property stays a <see cref="DateTimeOffset"/>; only the column
/// changes.
/// </para>
/// <para>
/// <b>Two things change on a round trip, both on purpose.</b> The offset is discarded and the
/// instant is kept, so a value written as <c>12:00+02:00</c> reads back as <c>10:00+00:00</c> - the
/// same moment, described from UTC. And the resolution is milliseconds, so <c>.1683914</c> reads
/// back as <c>.168</c>. Both are right for the audit timestamps this package stores, and both are
/// visible enough that somebody will eventually notice, so they are written down here rather than
/// left to be discovered. Do not use these converters for a value whose original offset carries
/// meaning, or one that needs sub-millisecond precision.
/// </para>
/// </remarks>
internal static class InstantConverters
{
    internal static readonly ValueConverter<DateTimeOffset, long> Instant = new(
        value => value.ToUniversalTime().ToUnixTimeMilliseconds(),
        value => DateTimeOffset.FromUnixTimeMilliseconds(value));

    internal static readonly ValueConverter<DateTimeOffset?, long?> NullableInstant = new(
        value => value == null ? null : value.Value.ToUniversalTime().ToUnixTimeMilliseconds(),
        value => value == null ? null : DateTimeOffset.FromUnixTimeMilliseconds(value.Value));
}
