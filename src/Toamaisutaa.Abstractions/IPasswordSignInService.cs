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
/// The pair a successful sign-in returns. Serialised camelCase like everything else this package
/// emits - <c>accessToken</c>, not the OAuth <c>access_token</c> - so one convention covers the
/// whole API.
/// </summary>
public sealed record TokenPair
{
    public required string AccessToken { get; init; }

    public required string RefreshToken { get; init; }

    /// <summary>Seconds until the access token expires.</summary>
    public required int ExpiresIn { get; init; }

    public string TokenType => "Bearer";
}
