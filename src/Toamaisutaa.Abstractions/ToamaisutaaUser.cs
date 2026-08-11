namespace Toamaisutaa.Abstractions;

/// <summary>
/// The local user row. A plain object with no attributes and no navigation properties, so
/// Abstractions stays dependency-free and the EF layer is free to configure it however a given
/// provider needs. Reach external logins through <see cref="IExternalLoginStore"/> rather than a
/// navigation property.
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
    /// On the user rather than the password credential, because a second factor belongs to the
    /// person and not to one way of proving they are them - a user provisioned by an identity
    /// provider has no credential row to hang it off.
    /// <para>
    /// It is not compared on every bearer request. Doing so costs a database read per request
    /// forever, and the window it closes is bounded by <c>AccessTokenLifetime</c> anyway.
    /// </para>
    /// </remarks>
    public string SecurityStamp { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Thrown when a token's <c>toa_stamp</c> no longer matches the user's. The credential it was
/// issued against has changed, so the token is stale even though its signature and expiry are both
/// still good.
/// </summary>
public sealed class SecurityStampChangedException(string message) : Exception(message);
