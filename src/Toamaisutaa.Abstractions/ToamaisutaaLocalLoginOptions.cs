namespace Toamaisutaa.Abstractions;

/// <summary>
/// Everything read from the <c>LocalLogin</c> configuration section. Local password login is the
/// fallback for deployments that cannot run an identity provider; OIDC is the recommended path.
/// </summary>
public sealed class ToamaisutaaLocalLoginOptions
{
    // ── Token issuance ──

    /// <summary>Base64, at least 32 bytes. Signs the access tokens this package issues with HS256,
    /// unless <see cref="SigningKeys"/> is set. There is deliberately no generated fallback: a
    /// per-process key would invalidate every token on restart and disagree between instances,
    /// silently.</summary>
    public string? SigningKey { get; set; }

    /// <summary>
    /// Asymmetric signing keys, active one first. Every entry validates; the first also signs.
    /// Empty by default, which leaves <see cref="SigningKey"/> and HS256 in charge.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HS256 can only be checked by a process holding the secret, so a gateway or a second service
    /// cannot validate a token without also being handed the ability to mint one. These publish
    /// their public halves at <c>{EndpointPrefix}/.well-known/jwks.json</c>, which is the shape
    /// anything that already validates an identity provider's tokens knows how to read.
    /// </para>
    /// <para>
    /// Rotating means putting a new entry at the front and leaving the old one behind it. Tokens
    /// signed by a key that is no longer first keep validating until they expire, so the retired
    /// entry can be dropped once one <see cref="AccessTokenLifetime"/> has passed. An entry that is
    /// only ever going to validate may carry the public half alone.
    /// </para>
    /// </remarks>
    public IList<ToamaisutaaSigningKeyOptions> SigningKeys { get; set; } = [];

    /// <summary>The <c>iss</c> of locally issued tokens, and the value that tells the rest of the
    /// package a token is ours. Changing it invalidates every token in flight.</summary>
    public string Issuer { get; set; } = "toamaisutaa";

    /// <summary>Defaults to <c>Oidc:ClientId</c>, so local tokens satisfy the same audience check
    /// as the identity provider's.</summary>
    public string? Audience { get; set; }

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>How long a chain of rotated refresh tokens may live before the person has to sign
    /// in again. Rotation alone never ends a session that is used regularly.</summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);

    // ── Hashing ──

    /// <summary>PBKDF2-HMAC-SHA256 iterations. The OWASP figure, and the floor that startup
    /// validation enforces.</summary>
    public int Pbkdf2Iterations { get; set; } = 600_000;

    public int SaltSizeBytes { get; set; } = 16;

    public int HashSizeBytes { get; set; } = 32;

    /// <summary>
    /// Optional secret mixed into every password before derivation, as
    /// <c>HMAC-SHA256(pepper, password)</c>. Base64, at least 32 bytes. Off by default.
    /// </summary>
    /// <remarks>
    /// Its whole value is that it does not live in the database: a stolen dump alone cannot be
    /// attacked offline without it, so keep it in an environment variable or a secret store, never
    /// in the connection the database uses. Losing it makes every stored password unverifiable.
    /// </remarks>
    public string? Pepper { get; set; }

    /// <summary>Written into the hash of every new password, so a row says which pepper made it.
    /// Alphanumeric.</summary>
    public string PepperVersion { get; set; } = "1";

    /// <summary>
    /// Superseded peppers, keyed by the version marker they were written under. Kept only so rows
    /// from before a rotation can still be verified - each one rehashes to the current pepper the
    /// next time its owner logs in, and the entry can be dropped once none are left.
    /// </summary>
    public IDictionary<string, string> RetiredPeppers { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

    // ── Lockout ──

    public bool LockoutEnabled { get; set; } = true;

    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>Failures further apart than this do not accumulate.</summary>
    public TimeSpan LockoutWindow { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    // ── Passwords ──

    /// <summary>A length floor and nothing else, per NIST: no composition rules, no forced
    /// rotation. Add a breach-list check with <c>Toamaisutaa.PasswordValidation.Hibp</c>, which
    /// wraps this rather than replacing it, or your own <see cref="IPasswordValidator"/>.</summary>
    public int MinimumPasswordLength { get; set; } = 8;

    /// <summary>
    /// An upper bound, because the endpoint taking this is anonymous. HMAC already reduces anything
    /// past its block size to a fixed-width value before the iterations begin, so length beyond
    /// this buys no strength at all - it only gives an unauthenticated caller a way to make the
    /// server chew through a megabyte per request.
    /// </summary>
    public int MaximumPasswordLength { get; set; } = 128;

    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Longer than <see cref="PasswordResetTokenLifetime"/> on purpose: a reset link answers "I
    /// cannot sign in right now", read within minutes; an invitation waits on someone who was not
    /// expecting it, and a week is nearer how long that email actually sits unread.
    /// </summary>
    public TimeSpan InvitationTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Longer than <see cref="PasswordResetTokenLifetime"/> for the same reason the invitation
    /// lifetime is: nobody is locked out while this link sits unread, so there is no hurry, and a
    /// verification mail is routinely opened the following morning.
    /// </summary>
    public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Off by default. When on, <c>/auth/password/forgot</c> issues nothing for a credential whose
    /// address was never verified, so a reset link can only ever be sent to an address somebody has
    /// proven they hold.
    /// </summary>
    /// <remarks>
    /// It closes a real hole and opens a real one, so read both. An unverified address that is a
    /// typo, or that somebody else now owns, is an address a reset link should never reach. But
    /// every account already in the database has <see cref="ToamaisutaaPasswordCredential.EmailConfirmedAt"/>
    /// null, so switching this on takes password reset away from all of them at once - and the only
    /// way back is <c>/auth/email</c>, which needs the password they came here without. Verify the
    /// existing accounts first, or expect to reset them by hand.
    /// </remarks>
    public bool RequireVerifiedEmailForPasswordReset { get; set; }

    /// <summary>How often the opt-in cleanup service deletes expired refresh, reset, invitation and
    /// email verification rows.</summary>
    public TimeSpan TokenCleanupInterval { get; set; } = TimeSpan.FromHours(6);

    // ── Endpoints ──

    /// <summary>Off by default. When off, the registration endpoint is not mapped at all rather
    /// than answering 403.</summary>
    public bool AllowSelfRegistration { get; set; }

    public string EndpointPrefix { get; set; } = "/auth";

    public ToamaisutaaRateLimitOptions RateLimit { get; set; } = new();
}

/// <summary>
/// One entry of <see cref="ToamaisutaaLocalLoginOptions.SigningKeys"/>: a key id, and the key
/// material as either PEM or a JWK.
/// </summary>
/// <remarks>
/// Public because it is bound from configuration, and because a key rarely lives in a settings
/// file - an application reading one from a vault builds this list in code instead.
/// </remarks>
public sealed class ToamaisutaaSigningKeyOptions
{
    /// <summary>
    /// What a token carries in its <c>kid</c> header, and how a validator picks this key back out
    /// of the set. Required for <see cref="Pem"/>; optional for <see cref="Jwk"/>, which may carry
    /// its own. Anything stable and unique will do - a date, a version, a GUID.
    /// </summary>
    public string? Kid { get; set; }

    /// <summary>
    /// An RSA or EC key in PEM, private half included for the active entry. Set this or
    /// <see cref="Jwk"/>, not both.
    /// </summary>
    public string? Pem { get; set; }

    /// <summary>
    /// The same key as a JSON Web Key, the JSON object itself rather than a set. Set this or
    /// <see cref="Pem"/>, not both.
    /// </summary>
    public string? Jwk { get; set; }
}

/// <summary>
/// Per-IP limits on the unauthenticated endpoints. Lockout is per account, so it does nothing
/// against someone posting a different username every time - and every one of those attempts costs
/// a full key derivation, because the timing-equalisation rule says an unknown user must pay the
/// same price as a known one. Without this, that pair is a cheap denial of service.
/// </summary>
public sealed class ToamaisutaaRateLimitOptions
{
    public bool Enabled { get; set; } = true;

    public int PermitLimit { get; set; } = 10;

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}
