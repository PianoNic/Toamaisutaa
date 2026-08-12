namespace Toamaisutaa.Abstractions;

public interface IPasswordSignInService
{
    Task<SignInResult> SignInAsync(PasswordSignInRequest request, CancellationToken cancellationToken = default);

    /// <summary>Exchanges a refresh token for a new pair, rotating it. Reuse of an already-rotated
    /// token revokes the whole family, and every trusted device with it.</summary>
    Task<SignInResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the presented token's family. Never reports whether it existed, and deliberately
    /// leaves trusted devices alone - signing out is not a security event, and a device surviving it
    /// is the entire point of having trusted it.
    /// </summary>
    Task SignOutAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finishes a sign-in that stopped at <see cref="SignInOutcome.TwoFactorRequired"/>.
    /// </summary>
    Task<SignInResult> VerifyTwoFactorAsync(TwoFactorSignInRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks for a second factor from a session that is already signed in, so that a policy
    /// requiring a <i>fresh</i> one can be satisfied without signing out.
    /// </summary>
    Task<StepUpChallengeResult> BeginStepUpAsync(StepUpRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes a step-up: a new access token for the same session, and the session's stored
    /// second-factor state moved forward so a refresh does not undo it.
    /// </summary>
    /// <remarks>
    /// No refresh token comes back and the family is not rotated. Rotating here would mean a client
    /// that ignored a new refresh token presented a spent one at its next refresh, tripping reuse
    /// detection - so successfully proving your identity would end every session you have.
    /// </remarks>
    Task<StepUpResult> CompleteStepUpAsync(StepUpVerificationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Who is stepping up, and which of their sessions.
/// </summary>
/// <remarks>
/// Both come from the caller's token - <c>sub</c> and <c>toa_sid</c> - and are passed in rather than
/// read here, so <c>Core</c> still never learns what an HTTP request is.
/// </remarks>
public sealed record StepUpRequest
{
    public required Guid UserId { get; init; }

    /// <summary>The refresh family from <c>toa_sid</c>. The session being elevated, and only it.</summary>
    public required Guid SessionId { get; init; }
}

public sealed record StepUpVerificationRequest
{
    public required Guid UserId { get; init; }

    public required Guid SessionId { get; init; }

    public required string ChallengeToken { get; init; }

    /// <summary>A TOTP code or a recovery code, as everywhere else.</summary>
    public required string Code { get; init; }
}

public sealed record StepUpChallengeResult
{
    public required SignInOutcome Outcome { get; init; }

    public TwoFactorChallenge? Challenge { get; init; }

    public bool Succeeded => Outcome == SignInOutcome.Succeeded;
}

public sealed record StepUpResult
{
    public required SignInOutcome Outcome { get; init; }

    /// <summary>A new access token for the same session. There is no new refresh token.</summary>
    public string? AccessToken { get; init; }

    public int ExpiresIn { get; init; }

    /// <summary>Set when a recovery code was spent to step up and few remain.</summary>
    public bool RecoveryCodesRunningLow { get; init; }

    public bool Succeeded => Outcome == SignInOutcome.Succeeded;
}

/// <summary>
/// Everything a sign-in attempt carries.
/// </summary>
/// <remarks>
/// A record rather than an argument list, for the reason <see cref="AccessTokenRequest"/> is one:
/// this signature has now needed widening in consecutive releases, and a third time would be a
/// pattern rather than an incident. It also keeps the transport out of <c>Core</c> - the endpoint
/// reads the user agent and address from the request and puts them here, so nothing below the web
/// layer has to know what an HTTP request is.
/// </remarks>
public sealed record PasswordSignInRequest
{
    /// <summary>A user name or an email address; the caller does not have to know which.</summary>
    public required string Identifier { get; init; }

    public required string Password { get; init; }

    /// <summary>
    /// A token from a previously trusted device. When it validates, the second factor is treated as
    /// already satisfied and no challenge is issued. Never a substitute for the password, which is
    /// verified first regardless.
    /// </summary>
    public string? DeviceToken { get; init; }

    public string? UserAgent { get; init; }

    public string? IpAddress { get; init; }
}

public sealed record TwoFactorSignInRequest
{
    public required string ChallengeToken { get; init; }

    /// <summary>A TOTP code or a recovery code; the caller does not have to say which.</summary>
    public required string Code { get; init; }

    /// <summary>
    /// Ask for a device token in the response. Honoured only here, never on a sign-in that was
    /// itself device-trusted - otherwise a family could renew itself indefinitely and its absolute
    /// lifetime would mean nothing.
    /// </summary>
    public bool RememberDevice { get; init; }

    public string? DeviceLabel { get; init; }

    public string? UserAgent { get; init; }

    public string? IpAddress { get; init; }
}

public sealed record SignInResult
{
    public required SignInOutcome Outcome { get; init; }

    public TokenPair? Tokens { get; init; }

    /// <summary>
    /// Set only when <see cref="Outcome"/> is <see cref="SignInOutcome.TwoFactorRequired"/>. Present
    /// it, with a code, to finish signing in.
    /// </summary>
    public TwoFactorChallenge? Challenge { get; init; }

    /// <summary>Set when a recovery code was spent to get here and few remain.</summary>
    public bool RecoveryCodesRunningLow { get; init; }

    /// <summary>
    /// Set only when the caller asked to be remembered and the second factor was actually presented.
    /// Hand it back on the next sign-in to skip the challenge.
    /// </summary>
    public TrustedDeviceToken? TrustedDevice { get; init; }

    public bool Succeeded => Outcome == SignInOutcome.Succeeded;
}

/// <summary>
/// A device token, handed out once. Store it where JavaScript cannot read it - see the
/// documentation, because the storage choice is the whole security of this feature.
/// </summary>
public sealed record TrustedDeviceToken(string Token, int ExpiresIn);

/// <summary>
/// The half-finished sign-in, handed to the caller so they can come back with a second factor.
/// </summary>
/// <remarks>
/// Opaque random bytes, not a signed token. A JWT challenge would be structurally a valid bearer
/// token held out of the API only by a validation rule, and rules are configuration a consumer can
/// loosen. This one cannot be presented as a bearer token at all.
/// </remarks>
public sealed record TwoFactorChallenge(string Token, int ExpiresIn);

/// <summary>
/// Why a sign-in ended the way it did. This is for your logs: the endpoints collapse every failure
/// into one response, because telling a caller which of these happened tells them whether an
/// account exists.
/// </summary>
public enum SignInOutcome
{
    Succeeded,
    UnknownUser,
    InvalidPassword,
    LockedOut,

    /// <summary>The account exists but has no password - an identity provider owns it.</summary>
    NoLocalCredential,

    InvalidRefreshToken,
    RefreshTokenExpired,

    /// <summary>An already-rotated token was presented, so two parties hold the chain.</summary>
    RefreshTokenReused,

    RefreshTokenRevoked,

    /// <summary>
    /// The credential was correct and the account carries a confirmed second factor. Not a failure:
    /// the result carries a challenge, and no tokens.
    /// </summary>
    TwoFactorRequired,

    /// <summary>Neither a TOTP code within the drift window nor an unspent recovery code.</summary>
    InvalidTwoFactorCode,

    InvalidChallenge,

    ChallengeExpired,

    /// <summary>A challenge is spent the moment it works. Presenting it again fails.</summary>
    ChallengeAlreadyUsed,

    /// <summary>
    /// The refresh chain was minted before a credential changed. The whole family is revoked, which
    /// is what a password change or a disabled second factor is supposed to do to old sessions.
    /// </summary>
    SecurityStampChanged,

    /// <summary>
    /// The caller's token carries no <c>toa_sid</c>, so it belongs to no session this package
    /// issued - an identity provider's token, most likely. There is nothing here to elevate.
    /// </summary>
    NotALocalSession,

    /// <summary>Step-up was asked for by a user with no confirmed second factor to present.</summary>
    TwoFactorNotEnrolled,

    /// <summary>
    /// The session named by <c>toa_sid</c> has no live refresh row: it was signed out or revoked
    /// while its access token was still inside its lifetime. Elevating it would resurrect something
    /// the user deliberately ended.
    /// </summary>
    SessionEnded,
}

/// <summary>How the second factor was satisfied. Written to <c>toa_2fa_source</c>.</summary>
public static class TwoFactorSource
{
    public const string Otp = "otp";

    public const string Recovery = "recovery";

    /// <summary>Cached from an earlier live challenge on a trusted device.</summary>
    public const string Device = "device";
}

/// <summary>
/// The pair a successful sign-in returns. The endpoints serialise it under the RFC 6749 names -
/// <c>access_token</c>, <c>refresh_token</c>, <c>expires_in</c>, <c>token_type</c> - so a client
/// that already speaks OAuth token endpoints reads it without a mapping.
/// </summary>
public sealed record TokenPair
{
    public required string AccessToken { get; init; }

    public required string RefreshToken { get; init; }

    /// <summary>Seconds until the access token expires.</summary>
    public required int ExpiresIn { get; init; }

    public string TokenType => "Bearer";
}
