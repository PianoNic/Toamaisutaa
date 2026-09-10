namespace Toamaisutaa.Passkeys;

/// <summary>Everything read from the <c>Passkeys</c> configuration section.</summary>
public sealed class ToamaisutaaPasskeyOptions
{
    // ── Relying party ──

    /// <summary>
    /// The domain a credential is bound to - <c>example.com</c>, never a scheme and never a port.
    /// Required, and there is no default on purpose.
    /// </summary>
    /// <remarks>
    /// It is the whole of what stops a phishing site using a credential: the browser refuses to
    /// sign for a relying party that is not a suffix of the page's own origin. Getting it wrong is
    /// also permanent for existing credentials, because every one already registered is bound to
    /// the old value and cannot be re-bound.
    /// </remarks>
    public string? RelyingPartyId { get; set; }

    /// <summary>What the browser's own prompt calls this site. Defaults to
    /// <see cref="RelyingPartyId"/>, which is at least honest if not friendly.</summary>
    public string? RelyingPartyName { get; set; }

    /// <summary>
    /// The full origins a ceremony may come from, scheme and port included -
    /// <c>https://example.com</c>. Required, and checked against what the browser reported.
    /// </summary>
    /// <remarks>
    /// A list rather than one value because a single deployment routinely has several: the site
    /// itself, a staging host, and <c>http://localhost:5173</c> for whoever is building the client.
    /// </remarks>
    public IList<string> Origins { get; set; } = [];

    // ── Ceremony ──

    /// <summary>
    /// On by default. The authenticator must verify the user - a PIN, a fingerprint, a face - and
    /// not merely confirm that somebody touched it.
    /// </summary>
    /// <remarks>
    /// This is what makes one ceremony worth two factors, and what lets a passkey sign-in satisfy
    /// <see cref="Abstractions.TwoFactorEnforcement.RequiredForAll"/> without a TOTP code on top.
    /// Turning it off leaves possession alone, so the resulting token carries no <c>mfa</c> and
    /// those policies start failing - which is correct, and is why turning it off is a decision
    /// rather than a tuning knob. An unverified assertion for an account with a confirmed TOTP
    /// enrolment stops for that code, the same as a password would.
    /// </remarks>
    public bool RequireUserVerification { get; set; } = true;

    /// <summary>How long a begun ceremony stays completable. Short, because the browser prompt is
    /// already open when it starts.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How recently the calling session must have presented a live second factor for that to stand
    /// in for the current password when registering a credential.
    /// </summary>
    /// <remarks>
    /// Registering a passkey adds a way of signing in, so a bearer token on its own must not be
    /// enough: a token lifted from a log line or a compromised browser would otherwise buy an
    /// attacker a credential that outlives every session the account holder can revoke. The caller
    /// sends their current password, or arrives on a session whose <c>toa_2fa_at</c> falls inside
    /// this window - the same claim <c>RequireFreshSecondFactor</c> reads, so "fresh" means one
    /// thing across the package.
    /// </remarks>
    public TimeSpan RegistrationProofWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// What the browser is told to wait, in milliseconds, before it gives up on its own prompt.
    /// Advisory - the authoritative deadline is <see cref="ChallengeLifetime"/>, which is enforced
    /// on the server.
    /// </summary>
    public uint TimeoutMilliseconds { get; set; } = 60_000;

    /// <summary>
    /// Zero means unlimited. A cap because every credential is a way into the account and a list
    /// nobody prunes grows one entry per browser, forever.
    /// </summary>
    public int MaxCredentialsPerUser { get; set; } = 10;

    // ── Endpoints ──

    /// <summary>
    /// Composed onto <see cref="Abstractions.ToamaisutaaLocalLoginOptions.EndpointPrefix"/>, the
    /// same way the trusted-device endpoints append <c>/devices</c>. A relative suffix rather than
    /// a full path, so moving local login moves these with it instead of stranding them.
    /// </summary>
    public string EndpointPrefix { get; set; } = "/passkeys";
}
