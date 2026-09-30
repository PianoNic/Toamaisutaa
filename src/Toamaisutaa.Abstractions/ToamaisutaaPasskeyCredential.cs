namespace Toamaisutaa.Abstractions;

/// <summary>
/// One WebAuthn credential a user registered. A user may have several.
/// </summary>
public class ToamaisutaaPasskeyCredential
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>
    /// What the authenticator calls this credential. Unique across every account, because sign-in
    /// is handed only this to find the owner.
    /// </summary>
    public byte[] CredentialId { get; set; } = default!;

    /// <summary>The COSE public key, as the authenticator encoded it.</summary>
    public byte[] PublicKey { get; set; } = default!;

    /// <summary>
    /// The authenticator's own counter, as of the last accepted assertion. A value that fails to
    /// advance reveals a cloned authenticator.
    /// </summary>
    /// <remarks>
    /// A <see cref="long"/> for WebAuthn's unsigned 32-bit value, because a signed 32-bit column would
    /// turn a counter near <c>uint.MaxValue</c> negative and read as a rollback.
    /// </remarks>
    public long SignCount { get; set; }

    /// <summary>
    /// The authenticator model, as the attestation reported it. All-zero for authenticators that
    /// decline to identify themselves.
    /// </summary>
    public Guid AaGuid { get; set; }

    /// <summary>
    /// How the authenticator can be reached - <c>usb</c>, <c>nfc</c>, <c>internal</c> and the rest,
    /// space-separated. Replayed to the browser at sign-in.
    /// </summary>
    public string? Transports { get; set; }

    /// <summary>The attestation statement format, <c>none</c> for the great majority.</summary>
    public string? AttestationFormat { get; set; }

    /// <summary>True when the authenticator says this credential may be copied to another device -
    /// a synced passkey rather than one bound to the hardware in front of you.</summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>True when it currently is copied. Updated on every assertion, because the user can
    /// turn sync on or off.</summary>
    public bool IsBackedUp { get; set; }

    /// <summary>What the user called it. Never used to find a row.</summary>
    public string? Label { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Null until it has signed something.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
}

/// <summary>
/// The server's half of a WebAuthn ceremony, held between the two calls it takes.
/// </summary>
/// <remarks>
/// <see cref="Options"/> is stored rather than round-tripped through the client, because the
/// completion step checks the authenticator against it and a client could otherwise hand back
/// different rules.
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
