namespace Toamaisutaa.Abstractions;

/// <summary>
/// The local credential for a user. A user has zero or one of these and any number of external
/// logins.
/// </summary>
/// <remarks>
/// Separate from <see cref="ToamaisutaaUser"/> because OIDC provisioning rewrites
/// <see cref="ToamaisutaaUser.Email"/>, while these login identifiers change only through an
/// explicit account operation.
/// </remarks>
public class ToamaisutaaPasswordCredential
{
    /// <summary>Primary key and foreign key both: one credential per user.</summary>
    public Guid UserId { get; set; }

    public string UserName { get; set; } = default!;

    /// <summary>Upper-invariant. Unique. Normalised in the application rather than by database
    /// collation, so it behaves the same on every provider.</summary>
    public string NormalizedUserName { get; set; } = default!;

    public string? Email { get; set; }

    /// <summary>Upper-invariant. Unique where present; null where the account has no address.</summary>
    public string? NormalizedEmail { get; set; }

    /// <summary>
    /// When somebody redeemed a token mailed to <see cref="Email"/>, and null until then. On the
    /// credential rather than the user because it proves the login identifier, not the profile
    /// address an identity provider writes.
    /// </summary>
    public DateTimeOffset? EmailConfirmedAt { get; set; }

    /// <summary>A self-describing PHC string naming the algorithm and its parameters.</summary>
    public string PasswordHash { get; set; } = default!;

    public int FailedAttemptCount { get; set; }

    public DateTimeOffset? FirstFailedAttemptAt { get; set; }

    public DateTimeOffset? LockedOutUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
