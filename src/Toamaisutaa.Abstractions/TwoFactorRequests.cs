namespace Toamaisutaa.Abstractions;

/// <summary><see cref="Code"/> comes from the authenticator app that just scanned the QR code. It
/// proves the app actually holds the secret, which is what turns the enrolment on.</summary>
public sealed record ConfirmTwoFactorRequest(string Code);

/// <summary><see cref="Proof"/> is a current TOTP code or an unspent recovery code. An
/// authenticated session is not enough on its own: a stolen access token must not be able to switch
/// the second factor off.</summary>
public sealed record DisableTwoFactorRequest(string Proof);

/// <summary>Same proof requirement as disabling, and it invalidates every previous code.</summary>
public sealed record RegenerateRecoveryCodesRequest(string Proof);

/// <summary>
/// Finishes a sign-in that stopped for a second factor. <see cref="Code"/> takes either a TOTP code
/// or a recovery code - one field, because the person typing it should not have to tell us which
/// kind they are holding when the shape already says.
/// </summary>
public sealed record VerifyTwoFactorRequest(
    string Challenge,
    string Code,
    bool RememberDevice = false,
    string? DeviceLabel = null);
