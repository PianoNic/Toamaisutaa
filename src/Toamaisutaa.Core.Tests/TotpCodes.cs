using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Generates the code an authenticator app would be showing, so the tests can drive a real
/// enrolment instead of stubbing verification out.
/// </summary>
/// <remarks>
/// Written out again rather than calling into the provider under test. It is only a few lines, and
/// having the tests generate codes with the same method they are checking would make an
/// implementation that is consistently wrong look right. The RFC 6238 vectors are what prove the
/// provider correct; this only has to agree with them.
/// </remarks>
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
