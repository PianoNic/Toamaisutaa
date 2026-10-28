using System.Text.Json.Serialization;

namespace Toamaisutaa.Passkeys;

/// <summary>
/// What <c>/register/begin</c> asks for before it will start a ceremony: proof that whoever is
/// calling holds a credential this account already has.
/// </summary>
/// <remarks>
/// A bearer token is not that proof: a passkey signs in on its own, so a stolen token must not be
/// enough to add one.
/// </remarks>
public sealed record PasskeyRegistrationProof
{
    /// <summary>
    /// The account's current password, required to register on an account with one and no TOTP
    /// enrolment. To remove a passkey, a session which presented a second factor within
    /// <c>Passkeys:RegistrationProofWindow</c> may leave it out.
    /// </summary>
    [JsonPropertyName("currentPassword")]
    public string? CurrentPassword { get; init; }

    /// <summary>
    /// A TOTP or recovery code. Required to register a passkey on an account with a confirmed TOTP
    /// enrolment, whatever else is sent, and counted against lockout like any wrong code.
    /// </summary>
    [JsonPropertyName("code")]
    public string? Code { get; init; }

    /// <summary>
    /// When the calling session last presented a live second factor, read from <c>toa_2fa_at</c>.
    /// </summary>
    /// <remarks>
    /// Filled in by the endpoint from the caller's token and ignored by the serialiser, so a caller
    /// cannot vouch for themselves in the body.
    /// </remarks>
    [JsonIgnore]
    public DateTimeOffset? SecondFactorAt { get; init; }
}

/// <summary>
/// What <c>navigator.credentials.create()</c> produced, flattened to base64url strings.
/// </summary>
/// <remarks>
/// This package's own shape rather than the FIDO2 library's, so the wire names survive both a
/// library upgrade and an application's own JSON naming policy.
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
public sealed record PasskeySecondFactorBeginRequest
{
    [JsonPropertyName("signInChallenge")]
    public required string SignInChallenge { get; init; }
}

/// <summary>
/// A passkey answering the second-factor challenge a password or magic-link sign-in returned.
/// </summary>
public sealed record PasskeySecondFactorRequest
{
    /// <summary>The <c>challenge</c> from <c>/auth/login</c> or <c>/auth/magic-link/verify</c>.</summary>
    [JsonPropertyName("signInChallenge")]
    public required string SignInChallenge { get; init; }

    /// <summary>The assertion, its <c>challenge</c> being the one <c>/second-factor/begin</c> returned.</summary>
    [JsonPropertyName("assertion")]
    public required PasskeyAssertionRequest Assertion { get; init; }
}

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
    /// practice, because sign-in begins without an identifier.
    /// </summary>
    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; init; }

    /// <summary>
    /// Where the request came from, for the session list. Filled in by the endpoint from the
    /// request itself.
    /// </summary>
    /// <remarks>
    /// Ignored by the serialiser, so a caller cannot describe their session as whatever they like.
    /// </remarks>
    [JsonIgnore]
    public string? UserAgent { get; init; }

    /// <summary>Null unless <c>LocalLogin:IpAddressStorage</c> says otherwise. Filled in by the
    /// endpoint and ignored by the serialiser.</summary>
    [JsonIgnore]
    public string? IpAddress { get; init; }
}
