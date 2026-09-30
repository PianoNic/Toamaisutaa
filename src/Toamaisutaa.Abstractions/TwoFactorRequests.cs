namespace Toamaisutaa.Abstractions;

/// <summary><see cref="CurrentPassword"/> is optional only for a caller who signed in within
/// <c>TwoFactor:EnrolmentProofWindow</c>, which the endpoint reads off their token.</summary>
public sealed record BeginTwoFactorRequest(string? CurrentPassword = null);

/// <summary><see cref="Code"/> comes from the authenticator app that just scanned the QR code, and
/// turns the enrolment on.</summary>
public sealed record ConfirmTwoFactorRequest(string Code);

/// <summary><see cref="Proof"/> is a current TOTP code or an unspent recovery code. An
/// authenticated session is not enough on its own: a stolen access token must not be able to switch
/// the second factor off.</summary>
public sealed record DisableTwoFactorRequest(string Proof);

/// <summary>Same proof requirement as disabling, and it invalidates every previous code.</summary>
public sealed record RegenerateRecoveryCodesRequest(string Proof);

/// <summary>
/// Finishes a sign-in that stopped for a second factor. <see cref="Code"/> takes either a TOTP code
/// or a recovery code.
/// </summary>
public sealed record VerifyTwoFactorRequest(
    string Challenge,
    string Code,
    bool RememberDevice = false,
    string? DeviceLabel = null);

/// <summary>
/// Completes a step-up. <see cref="Code"/> takes a TOTP code or a recovery code, as everywhere else.
/// </summary>
/// <remarks>
/// <b>There is deliberately no device token field.</b> Step-up exists to refuse a cached second
/// factor, and an absent field cannot be loosened the way a check could.
/// </remarks>
public sealed record StepUpVerifyRequest(string Challenge, string Code);
