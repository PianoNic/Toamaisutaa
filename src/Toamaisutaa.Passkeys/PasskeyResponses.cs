using System.Text.Json;
using System.Text.Json.Serialization;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// What both begin endpoints return: the opaque challenge, how long it lasts, and the WebAuthn
/// options to hand to the browser.
/// </summary>
/// <remarks>
/// snake_case for <c>expires_in</c>, matching the two-factor challenge bodies next to it - these
/// sit on the sign-in path, where the rest of the package is OAuth-shaped. <c>options</c> is passed
/// through exactly as the specification defines it, so a client library reads it unaltered.
/// </remarks>
public sealed record PasskeyChallengeResponse
{
    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    /// <summary>Seconds until the challenge expires.</summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    /// <summary>The WebAuthn options, base64url fields and all.</summary>
    [JsonPropertyName("options")]
    public required JsonElement Options { get; init; }
}
