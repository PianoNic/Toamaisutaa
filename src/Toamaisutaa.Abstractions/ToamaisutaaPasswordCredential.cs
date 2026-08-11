namespace Toamaisutaa.Abstractions;

/// <summary>
/// The local credential for a user, in its own table rather than as columns on
/// <see cref="ToamaisutaaUser"/>. A user has zero or one of these and any number of external
/// logins, so the two sign-in paths coexist on one account.
/// </summary>
/// <remarks>
/// The separation is not tidiness. <see cref="ToamaisutaaUser.Email"/> is a profile field that OIDC
/// provisioning rewrites whenever the token's claim changes; the identifier someone types into a
/// login form must not move because an administrator edited a directory. These are the login
/// identifiers, and nothing but an explicit account operation writes them.
/// </remarks>
public class ToamaisutaaPasswordCredential
{
    /// <summary>Primary key and foreign key both: one credential per user.</summary>
    public Guid UserId { get; set; }

    public string UserName { get; set; } = default!;

    /// <summary>Upper-invariant. Unique. Normalised in the application rather than left to database
    /// collation, so identity does not mean different things on different providers.</summary>
    public string NormalizedUserName { get; set; } = default!;

    public string? Email { get; set; }

    /// <summary>Upper-invariant. Unique where present; null where the account has no address, which
    /// both supported providers treat as distinct rather than colliding.</summary>
    public string? NormalizedEmail { get; set; }

    /// <summary>A self-describing PHC string naming the algorithm and its parameters, so changing
    /// either is a rehash on next login rather than a schema change.</summary>
    public string PasswordHash { get; set; } = default!;

    public int FailedAttemptCount { get; set; }

    public DateTimeOffset? FirstFailedAttemptAt { get; set; }

    public DateTimeOffset? LockedOutUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
