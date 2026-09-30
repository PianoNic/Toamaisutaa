namespace Toamaisutaa.Abstractions;

/// <summary>
/// Everything read from the <c>LocalLogin</c> configuration section. Local password login is the
/// fallback for deployments that cannot run an identity provider; OIDC is the recommended path.
/// </summary>
public sealed class ToamaisutaaLocalLoginOptions
{
    /// <summary>Base64, at least 32 bytes. Signs the access tokens this package issues with HS256,
    /// unless <see cref="SigningKeys"/> is set. There is deliberately no generated fallback, which
    /// would silently invalidate tokens on restart and disagree between instances.</summary>
    public string? SigningKey { get; set; }

    /// <summary>
    /// Asymmetric signing keys, active one first. Every entry validates; the first also signs.
    /// Empty by default, which leaves <see cref="SigningKey"/> and HS256 in charge.
    /// </summary>
    /// <remarks>
    /// Public halves are published at <c>{EndpointPrefix}/.well-known/jwks.json</c>. To rotate, put
    /// the new entry at the front and drop the old one once one <see cref="AccessTokenLifetime"/> has
    /// passed. A validate-only entry may carry the public half alone.
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
    /// Keep it out of the database (an environment variable or secret store), or it protects nothing.
    /// Losing it makes every stored password unverifiable.
    /// </remarks>
    public string? Pepper { get; set; }

    /// <summary>Written into the hash of every new password, so a row says which pepper made it.
    /// Alphanumeric.</summary>
    public string PepperVersion { get; set; } = "1";

    /// <summary>
    /// Superseded peppers, keyed by version marker, so rows from before a rotation still verify.
    /// Each row rehashes to the current pepper at its owner's next login.
    /// </summary>
    public IDictionary<string, string> RetiredPeppers { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

    public bool LockoutEnabled { get; set; } = true;

    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>Failures further apart than this do not accumulate.</summary>
    public TimeSpan LockoutWindow { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The least time a refused <c>/auth/login</c> takes, so unknown users, wrong passwords and locked
    /// accounts are indistinguishable by timing. Raise it if hash verification is slower. Zero turns it off.
    /// </summary>
    public TimeSpan SignInRefusalFloor { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// How recently a caller must have authenticated to give a passwordless account its first
    /// password, so a lifted bearer token cannot add a way in that outlives it.
    /// </summary>
    public TimeSpan FirstPasswordProofWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>A length floor and nothing else, per NIST: no composition rules, no forced
    /// rotation. Add a breach-list check with <c>Toamaisutaa.PasswordValidation.Hibp</c>, which
    /// wraps this rather than replacing it, or your own <see cref="IPasswordValidator"/>.</summary>
    public int MinimumPasswordLength { get; set; } = 8;

    /// <summary>
    /// An upper bound, because the endpoint is anonymous and extra length buys no strength - it only
    /// lets an unauthenticated caller make the server hash huge inputs.
    /// </summary>
    public int MaximumPasswordLength { get; set; } = 128;

    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long after a reset or magic-link request for an address the next one is quietly dropped,
    /// and how long an account waits between email-change requests. Stops inbox flooding and relay
    /// abuse. Zero turns it off.
    /// </summary>
    public TimeSpan MailRequestCooldown { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Longer than <see cref="PasswordResetTokenLifetime"/> because an invitation often sits unread for days.
    /// </summary>
    public TimeSpan InvitationTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How long an email-verification link stays valid.</summary>
    public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Shorter than <see cref="PasswordResetTokenLifetime"/> because this link is itself the session,
    /// so a message left in a shared or forwarded mailbox must stop being a credential quickly.
    /// </summary>
    public TimeSpan MagicLinkTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Off by default. When on, <c>/auth/password/forgot</c> issues nothing for a credential whose
    /// address was never verified, and an administrator-set password is refused for it rather than
    /// mailed to it.
    /// </summary>
    /// <remarks>
    /// Every existing account with a null <see cref="ToamaisutaaPasswordCredential.EmailConfirmedAt"/>
    /// loses password reset (and administrator-set passwords) the moment this is switched on, so
    /// verify existing accounts first.
    /// </remarks>
    public bool RequireVerifiedEmailForPasswordReset { get; set; }

    /// <summary>How often the opt-in cleanup service deletes expired refresh, reset, invitation,
    /// email-verification and magic-link rows, plus expired two-factor challenge, trusted-device
    /// and passkey-challenge rows when those features are registered.</summary>
    public TimeSpan TokenCleanupInterval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>Off by default. When off, the registration endpoint is not mapped at all rather
    /// than answering 403.</summary>
    public bool AllowSelfRegistration { get; set; }

    public string EndpointPrefix { get; set; } = "/auth";

    /// <summary>A suffix composed onto <see cref="EndpointPrefix"/>, not a full path.</summary>
    public string SessionEndpointPrefix { get; set; } = "/sessions";

    /// <summary>
    /// How much of the caller's address to keep against a refresh family, so the session list can
    /// say where a session was established.
    /// </summary>
    public IpAddressStorage IpAddressStorage { get; set; } = IpAddressStorage.None;

    public ToamaisutaaRateLimitOptions RateLimit { get; set; } = new();
}

/// <summary>
/// One entry of <see cref="ToamaisutaaLocalLoginOptions.SigningKeys"/>: a key id, and the key
/// material as either PEM or a JWK.
/// </summary>
public sealed class ToamaisutaaSigningKeyOptions
{
    /// <summary>
    /// The token's <c>kid</c> header. Required for <see cref="Pem"/>; optional for <see cref="Jwk"/>,
    /// which may carry its own. Anything stable and unique.
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
/// Per-IP limits on the unauthenticated endpoints. Lockout is per account, and every unknown-user
/// attempt still costs a full key derivation, so without this they are a cheap denial of service.
/// </summary>
public sealed class ToamaisutaaRateLimitOptions
{
    public bool Enabled { get; set; } = true;

    public int PermitLimit { get; set; } = 10;

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Network-specific NAT64 prefixes in front of this deployment, such as <c>2001:db8:64::/96</c>,
    /// with a length of 32, 40, 48, 56, 64 or 96. A client behind one is keyed on the IPv4 address
    /// inside it, as it already is for the well-known <c>64:ff9b::/96</c> and <c>64:ff9b:1::/48</c>.
    /// </summary>
    /// <remarks>
    /// Without it, every IPv4 client behind the gateway shares one budget.
    /// </remarks>
    public IList<string> Nat64Prefixes { get; set; } = [];
}
