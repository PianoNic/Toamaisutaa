namespace Toamaisutaa.Abstractions;

/// <summary>
/// The local user row. Reach external logins through <see cref="IExternalLoginStore"/>.
/// </summary>
public class ToamaisutaaUser
{
    public Guid Id { get; set; }

    public string? UserName { get; set; }

    public string? Email { get; set; }

    public string? DisplayName { get; set; }

    public string? PictureUrl { get; set; }

    /// <summary>
    /// Changes whenever a credential changes: a password set, change or reset, and enabling,
    /// disabling or regenerating a second factor. Issued access tokens carry it, and it is compared
    /// on refresh and wherever <c>ICurrentUser</c> resolves a user, so a stale one ends the session.
    /// </summary>
    /// <remarks>
    /// It is not compared on every bearer request, so a stale token lives until
    /// <c>AccessTokenLifetime</c> runs out.
    /// </remarks>
    public string SecurityStamp { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Thrown when a token's <c>toa_stamp</c> no longer matches the user's, so the token is stale even
/// though its signature and expiry are still good.
/// </summary>
public sealed class SecurityStampChangedException(string message) : Exception(message);
