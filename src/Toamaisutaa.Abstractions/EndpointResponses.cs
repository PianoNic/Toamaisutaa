using System.Text.Json.Serialization;

namespace Toamaisutaa.Abstractions;

/// <summary>
/// The body every successful sign-in returns - <c>/auth/login</c>, <c>/auth/refresh</c>,
/// <c>/auth/register</c> and <c>/auth/2fa/verify</c>.
/// </summary>
/// <remarks>
/// <para>
/// A named type rather than an anonymous object because this is the wire contract of the most
/// important endpoint in the package. As an anonymous initialiser it could not be referenced by a
/// test, could not be declared to OpenAPI, and the RFC 6749 field names existed only as C#
/// identifiers that any rename would have quietly changed.
/// </para>
/// <para>
/// Every name is pinned with <see cref="JsonPropertyNameAttribute"/> rather than left to a naming
/// policy. An application that configures its own <c>JsonOptions</c> - snake_case everywhere, say,
/// or no policy at all - would otherwise reshape a standard token response by accident.
/// </para>
/// </remarks>
public sealed record TokenResponse
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; init; }

    /// <summary>Seconds until <see cref="AccessToken"/> expires.</summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// <see langword="true"/> when a recovery code was spent to get here and few remain, and
    /// <see langword="null"/> otherwise - never <see langword="false"/>. That asymmetry is the shape
    /// 0.2.0 shipped and clients read it as truthy-or-absent, so it stays.
    /// </summary>
    [JsonPropertyName("recovery_codes_running_low")]
    public bool? RecoveryCodesRunningLow { get; init; }

    /// <summary>
    /// Set when the caller asked to be remembered and the second factor was live, and on every
    /// device-trusted sign-in, which rotates the token. Store the new one and discard the old.
    /// </summary>
    [JsonPropertyName("device_token")]
    public string? DeviceToken { get; init; }

    /// <summary>
    /// Seconds until the device trust expires. Measured from when the family was established, so
    /// rotation returns a smaller number each time rather than starting again.
    /// </summary>
    [JsonPropertyName("device_expires_in")]
    public int? DeviceExpiresIn { get; init; }
}

/// <summary>
/// The second success shape of <c>/auth/login</c>: the password was right and the account carries a
/// confirmed second factor, so there are no tokens yet.
/// </summary>
/// <remarks>
/// A 200 rather than a new status code, so the branch is explicit and cannot be missed by a client
/// that only checks for success. Present <see cref="Challenge"/> with a code to
/// <c>/auth/2fa/verify</c>.
/// </remarks>
public sealed record TwoFactorChallengeResponse
{
    /// <summary>Always <see langword="true"/>. It exists so a client can branch on one field.</summary>
    [JsonPropertyName("two_factor_required")]
    public bool TwoFactorRequired { get; init; } = true;

    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    /// <summary>Seconds until the challenge expires.</summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }
}

/// <summary>
/// What <c>/auth/2fa/step-up</c> returns: a challenge for a session that is already signed in.
/// </summary>
/// <remarks>
/// Not <see cref="TwoFactorChallengeResponse"/>, close as the shape is. That one carries
/// <c>two_factor_required: true</c>, which would be a lie here - nothing is required, the caller
/// asked.
/// </remarks>
public sealed record StepUpChallengeResponse
{
    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    /// <summary>Seconds until the challenge expires.</summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }
}

/// <summary>
/// What <c>/auth/2fa/step-up/verify</c> returns: a new access token for the same session.
/// </summary>
/// <remarks>
/// Not <see cref="TokenResponse"/>, because there is no refresh token. Sharing that type would put
/// <c>refresh_token: null</c> on every step-up, and a client that stored what came back would blank
/// the credential it needs to stay signed in.
/// </remarks>
public sealed record StepUpResponse
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// True or absent, never false - the same shape as the field on <see cref="TokenResponse"/>,
    /// because a recovery code can be spent here too.
    /// </summary>
    [JsonPropertyName("recovery_codes_running_low")]
    public bool? RecoveryCodesRunningLow { get; init; }
}

/// <summary>
/// A credential that was not accepted. RFC 6749 section 5.2 names these fields, so anything that
/// already reads OAuth error bodies reads this one.
/// </summary>
/// <remarks>
/// One body for every way a sign-in can fail. Wrong password, no such account, locked out and an
/// unknown refresh token are the same answer, because telling them apart tells a caller which user
/// names are real.
/// </remarks>
public sealed record ErrorResponse
{
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    [JsonPropertyName("error_description")]
    public required string ErrorDescription { get; init; }
}

/// <summary>
/// Input the caller can correct: the password they chose, a reset link that has expired, a user name
/// already taken.
/// </summary>
/// <remarks>
/// camelCase, unlike the token and error bodies above. No standard names this shape, so it follows
/// the same rule as the rest of the package's own responses. The mix is deliberate: token endpoints
/// are OAuth-shaped, everything else is ours.
/// </remarks>
public sealed record ValidationErrorResponse
{
    [JsonPropertyName("errors")]
    public required IReadOnlyList<string> Errors { get; init; }
}
