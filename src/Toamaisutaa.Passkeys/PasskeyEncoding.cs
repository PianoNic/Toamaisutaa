namespace Toamaisutaa.Passkeys;

/// <summary>
/// base64url, as WebAuthn responses carry every binary field.
/// </summary>
/// <remarks>
/// Tolerant of standard base64 and of padding either way, because the encoding happens in whatever
/// the client is written in: <c>btoa</c> plus two replaces, a helper from a WebAuthn library, or a
/// mobile SDK, and they do not agree on the alphabet or on trailing <c>=</c>. Rejecting one of the
/// three would surface as a passkey that mysteriously fails on one platform.
/// </remarks>
internal static class PasskeyEncoding
{
    /// <summary>Throws <see cref="FormatException"/> for anything that is neither.</summary>
    internal static byte[] Decode(string value)
    {
        var normalised = value.Replace('-', '+').Replace('_', '/').TrimEnd('=');

        return Convert.FromBase64String(normalised.PadRight(normalised.Length + ((4 - (normalised.Length % 4)) % 4), '='));
    }
}
