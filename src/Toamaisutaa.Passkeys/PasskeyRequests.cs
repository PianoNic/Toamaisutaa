using System.Text.Json.Serialization;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// What <c>/register/begin</c> asks for before it will start a ceremony: proof that whoever is
/// calling holds a credential this account already has.
/// </summary>
/// <remarks>
/// A bearer token is not that proof. A passkey signs in on its own, so adding one is adding a way
/// into the account - which puts this alongside changing an email address or disabling the second
/// factor rather than alongside reading a list, and a token lifted from a log line or a compromised
/// browser must not be enough to do it.
/// </remarks>
public sealed record PasskeyRegistrationProof
{
    /// <summary>The account's current password. Optional only in the sense that a session which
    /// presented a second factor within <c>Passkeys:RegistrationProofWindow</c> needs no
    /// password.</summary>
    [JsonPropertyName("currentPassword")]
    public string? CurrentPassword { get; init; }

    /// <summary>
    /// When the calling session last presented a live second factor, read from <c>toa_2fa_at</c>.
    /// </summary>
    /// <remarks>
    /// Filled in by the endpoint from the caller's own token, and ignored by the serialiser, so a
    /// caller cannot put a time in the body and vouch for themselves.
    /// </remarks>
    [JsonIgnore]
    public DateTimeOffset? SecondFactorAt { get; init; }
}

/// <summary>
/// What <c>navigator.credentials.create()</c> produced, flattened to base64url strings.
/// </summary>
/// <remarks>
/// This package's own shape rather than the FIDO2 library's, deliberately. The library's models are
/// its API and would put its field names, its converters and its next major version on this
/// package's wire contract; these names are pinned here and survive both a library upgrade and an
/// application's own JSON naming policy.
/// </remarks>
public sealed record PasskeyRegistrationRequest
{
    /// <summary>The opaque challenge from the begin step. Not the WebAuthn challenge.</summary>
    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    /// <summary>The credential id, base64url, as <c>credential.id</c> gives it.</summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>base64url of <c>response.attestationObject</c>.</summary>
    [JsonPropertyName("attestationObject")]
    public required string AttestationObject { get; init; }

    /// <summary>base64url of <c>response.clientDataJSON</c>.</summary>
    [JsonPropertyName("clientDataJson")]
    public required string ClientDataJson { get; init; }

    /// <summary>What <c>response.getTransports()</c> returned, if the browser implements it.
    /// Stored and replayed at sign-in so the prompt asks for the right thing.</summary>
    [JsonPropertyName("transports")]
    public IReadOnlyList<string>? Transports { get; init; }

    /// <summary>What to call this credential in the user's own list. Optional, and never used to
    /// find a row.</summary>
    [JsonPropertyName("label")]
    public string? Label { get; init; }
}

/// <summary>What <c>navigator.credentials.get()</c> produced, flattened to base64url strings.</summary>
public sealed record PasskeyAssertionRequest
{
    /// <summary>The opaque challenge from the begin step.</summary>
    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>base64url of <c>response.authenticatorData</c>.</summary>
    [JsonPropertyName("authenticatorData")]
    public required string AuthenticatorData { get; init; }

    /// <summary>base64url of <c>response.clientDataJSON</c>.</summary>
    [JsonPropertyName("clientDataJson")]
    public required string ClientDataJson { get; init; }

    /// <summary>base64url of <c>response.signature</c>.</summary>
    [JsonPropertyName("signature")]
    public required string Signature { get; init; }

    /// <summary>
    /// base64url of <c>response.userHandle</c>: which account the authenticator chose. Required in
    /// practice, because sign-in here begins without an identifier and this is the only thing that
    /// says who is arriving.
    /// </summary>
    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; init; }

    /// <summary>
    /// Where the request came from, for the session list. Filled in by the endpoint from the
    /// request itself.
    /// </summary>
    /// <remarks>
    /// Ignored by the serialiser, so a caller cannot set it in the body and describe their session
    /// as whatever they like. It lives on this record rather than on a second, near-identical one
    /// because there is no layering reason to keep it off: unlike <c>Core</c>, this package already
    /// references ASP.NET Core.
    /// </remarks>
    [JsonIgnore]
    public string? UserAgent { get; init; }

    /// <summary>Null unless <c>LocalLogin:IpAddressStorage</c> says otherwise. Filled in by the
    /// endpoint, and ignored by the serialiser for the same reason as above.</summary>
    [JsonIgnore]
    public string? IpAddress { get; init; }
}
