using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Written out again rather than calling the provider under test, so an implementation that is
/// consistently wrong cannot look right.
/// </summary>
internal static class TotpCodes
{
    internal static string Compute(byte[] secret, DateTimeOffset at, TimeSpan period, int digits)
    {
        var step = at.ToUnixTimeSeconds() / (long)period.TotalSeconds;

        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);

        var hash = HMACSHA1.HashData(secret, counter);

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        return (binary % (int)Math.Pow(10, digits))
            .ToString(CultureInfo.InvariantCulture)
            .PadLeft(digits, '0');
    }
}
