namespace Toamaisutaa.Passkeys;

/// <summary>Everything read from the <c>Passkeys</c> configuration section.</summary>
public sealed class ToamaisutaaPasskeyOptions
{
    /// <summary>
    /// The domain a credential is bound to - <c>example.com</c>, never a scheme and never a port.
    /// Required, with no default.
    /// </summary>
    /// <remarks>
    /// The browser refuses to sign for a relying party that is not a suffix of the page's origin,
    /// which is what stops phishing. Changing it is permanent: existing credentials stay bound to
    /// the old value and cannot be re-bound.
    /// </remarks>
    public string? RelyingPartyId { get; set; }

    /// <summary>What the browser's own prompt calls this site. Defaults to
    /// <see cref="RelyingPartyId"/>.</summary>
    public string? RelyingPartyName { get; set; }

    /// <summary>
    /// The full origins a ceremony may come from, scheme and port included -
    /// <c>https://example.com</c>. Required, and checked against what the browser reported.
    /// </summary>
    public IList<string> Origins { get; set; } = [];

    /// <summary>
    /// On by default. The authenticator must verify the user - a PIN, a fingerprint, a face - and
    /// not merely confirm that somebody touched it.
    /// </summary>
    /// <remarks>
    /// This is what lets a passkey sign-in carry <c>mfa</c> and satisfy
    /// <see cref="Abstractions.TwoFactorEnforcement.RequiredForAll"/> on its own. Turned off, tokens
    /// carry possession alone, those policies fail, and an account with a confirmed TOTP enrolment
    /// is asked for its code.
    /// </remarks>
    public bool RequireUserVerification { get; set; } = true;

    /// <summary>How long a begun ceremony stays completable.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How recently the calling session must have presented a live second factor for that to stand
    /// in for the current password when registering or removing a credential.
    /// </summary>
    /// <remarks>
    /// Read from the <c>toa_2fa_at</c> claim, the same one <c>RequireFreshSecondFactor</c> reads. A
    /// bearer token alone is never enough, since a stolen one would otherwise buy a credential that
    /// outlives every session the owner can revoke.
    /// </remarks>
    public TimeSpan RegistrationProofWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// What the browser is told to wait, in milliseconds, before it gives up on its own prompt.
    /// Advisory - the server enforces <see cref="ChallengeLifetime"/>.
    /// </summary>
    public uint TimeoutMilliseconds { get; set; } = 60_000;

    /// <summary>
    /// The most passkeys one account may register. Zero means unlimited.
    /// </summary>
    public int MaxCredentialsPerUser { get; set; } = 10;

    /// <summary>
    /// A relative suffix composed onto
    /// <see cref="Abstractions.ToamaisutaaLocalLoginOptions.EndpointPrefix"/>, so moving local login
    /// moves these with it.
    /// </summary>
    public string EndpointPrefix { get; set; } = "/passkeys";
}
