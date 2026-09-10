namespace Toamaisutaa.Abstractions;

/// <summary>
/// One WebAuthn credential a user registered. Several per account is the normal case - a phone, a
/// laptop and a security key are three - which is why this is a table rather than columns on the
/// user row.
/// </summary>
/// <remarks>
/// Here rather than in <c>Toamaisutaa.Passkeys</c>, alongside the other entities, because the
/// Entity Framework package configures it and ships the four providers' migrations. Putting it in
/// the opt-in package would mean the storage package referencing the feature package, which is the
/// dependency running the wrong way - see <c>design/passkeys-package-layering.md</c>.
/// </remarks>
public class ToamaisutaaPasskeyCredential
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>
    /// What the authenticator calls this credential. Unique across every account: the sign-in path
    /// is handed one of these and nothing else, so two rows sharing it would make "whose credential
    /// is this" unanswerable.
    /// </summary>
    public byte[] CredentialId { get; set; } = default!;

    /// <summary>The COSE public key, as the authenticator encoded it. Public by definition, so
    /// unlike a TOTP secret there is nothing here to encrypt.</summary>
    public byte[] PublicKey { get; set; } = default!;

    /// <summary>
    /// The authenticator's own counter, as of the last accepted assertion. A value that fails to
    /// advance is how a cloned authenticator gives itself away, which is the only reason to keep it.
    /// </summary>
    /// <remarks>
    /// A <see cref="long"/> for a value WebAuthn defines as an unsigned 32-bit integer: no provider
    /// here has an unsigned column type, and a counter near <c>uint.MaxValue</c> stored as a signed
    /// 32-bit integer would come back negative and read as a rollback that never happened.
    /// </remarks>
    public long SignCount { get; set; }

    /// <summary>
    /// The authenticator model, as the attestation reported it. All-zero for the platform
    /// authenticators that decline to identify themselves, which is most of them and is fine.
    /// </summary>
    public Guid AaGuid { get; set; }

    /// <summary>
    /// How the authenticator can be reached - <c>usb</c>, <c>nfc</c>, <c>internal</c> and the rest,
    /// space-separated. Replayed to the browser at sign-in so it can prompt for the right thing
    /// rather than offering every option at once.
    /// </summary>
    public string? Transports { get; set; }

    /// <summary>The attestation statement format, <c>none</c> for the great majority. Kept because
    /// it is the one durable record of how the credential arrived.</summary>
    public string? AttestationFormat { get; set; }

    /// <summary>True when the authenticator says this credential may be copied to another device -
    /// a synced passkey rather than one bound to the hardware in front of you.</summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>True when it currently is copied. Updated on every assertion, because it changes
    /// when the user turns their provider's sync on or off.</summary>
    public bool IsBackedUp { get; set; }

    /// <summary>What the user called it, so a list reads as "work laptop" rather than as a base64
    /// identifier. Never used to find a row.</summary>
    public string? Label { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Null until it has signed something. A list of passkeys is read to decide which one
    /// to delete, and "never used" is the most useful thing it can say about one.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
}

/// <summary>
/// The server's half of a WebAuthn ceremony, held between the two calls it takes.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Options"/> is stored rather than sent back for the client to return. The options
/// carry the challenge, the relying party id and the user verification requirement, and every one
/// of those is a rule the completion step checks the authenticator against - so a client that could
/// hand them back could hand back different ones and check itself.
/// </para>
/// <para>
/// The token that names this row is opaque random bytes for the same reason the two-factor
/// challenge is: it cannot be presented as a bearer token anywhere, rather than being kept out of
/// the API by a validation rule somebody could loosen.
/// </para>
/// </remarks>
public class ToamaisutaaPasskeyChallenge
{
    public Guid Id { get; set; }

    /// <summary>
    /// Null for an assertion begun without an identifier, which is the usual passwordless case: the
    /// browser picks a discoverable credential and the server learns who it is only at the end.
    /// </summary>
    public Guid? UserId { get; set; }

    /// <summary>SHA-256 of the raw token. Unique.</summary>
    public string TokenHash { get; set; } = default!;

    /// <summary>The WebAuthn options as JSON, exactly as they went to the browser.</summary>
    public string Options { get; set; } = default!;

    /// <summary>Which ceremony this belongs to. Each endpoint refuses the other's, so a
    /// registration challenge cannot be spent at the anonymous sign-in endpoint.</summary>
    public PasskeyCeremony Ceremony { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Set the moment it is spent. Presenting it again fails.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}

/// <summary>Which WebAuthn ceremony a challenge belongs to. Not interchangeable.</summary>
public enum PasskeyCeremony
{
    /// <summary>Registering a new credential against an account that is already signed in.</summary>
    Registration,

    /// <summary>Signing in with a credential that already exists. Redeemed anonymously.</summary>
    Assertion,
}
