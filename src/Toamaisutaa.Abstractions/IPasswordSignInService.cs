namespace Toamaisutaa.Abstractions;

public interface IPasswordSignInService
{
    /// <summary>Identifier is a user name or an email address; the caller does not have to know
    /// which.</summary>
    Task<SignInResult> SignInAsync(string identifier, string password, CancellationToken cancellationToken = default);

    /// <summary>Exchanges a refresh token for a new pair, rotating it. Reuse of an already-rotated
    /// token revokes the whole family.</summary>
    Task<SignInResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>Revokes the presented token's family. Never reports whether it existed.</summary>
    Task SignOutAsync(string refreshToken, CancellationToken cancellationToken = default);
}

public sealed record SignInResult
{
    public required SignInOutcome Outcome { get; init; }

    public TokenPair? Tokens { get; init; }

    public bool Succeeded => Outcome == SignInOutcome.Succeeded;
}

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
}

/// <summary>OAuth-shaped, so a client library that already speaks token endpoints can read it.</summary>
public sealed record TokenPair
{
    public required string AccessToken { get; init; }

    public required string RefreshToken { get; init; }

    /// <summary>Seconds until the access token expires.</summary>
    public required int ExpiresIn { get; init; }

    public string TokenType => "Bearer";
}
