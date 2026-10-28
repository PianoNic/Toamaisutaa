namespace Toamaisutaa.Abstractions;

/// <summary>
/// <see cref="Code"/> is what the return URL was handed; <see cref="CodeVerifier"/> is the secret whose
/// S256 hash the client passed to <c>/start</c> as <c>codeChallenge</c>.
/// </summary>
public sealed record ExternalLoginExchangeRequest(string Code, string CodeVerifier);

/// <summary>
/// Proof the caller holds the account, as for passkey registration: <see cref="Code"/> where the account
/// has a second factor, otherwise <see cref="CurrentPassword"/> where it has a password, otherwise
/// nothing beyond a sign-in moments ago.
/// </summary>
public sealed record LinkExternalLoginRequest(string ReturnUrl, string? State = null, string? CurrentPassword = null, string? Code = null);

/// <summary>The same proof <see cref="LinkExternalLoginRequest"/> takes.</summary>
public sealed record UnlinkExternalLoginRequest(string? CurrentPassword = null, string? Code = null);
