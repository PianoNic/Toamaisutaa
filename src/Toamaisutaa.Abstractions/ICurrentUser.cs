namespace Toamaisutaa.Abstractions;

/// <summary>
/// What application code injects to find out who is calling. Deliberately not HTTP-shaped, so a
/// domain or application layer can depend on it without referencing ASP.NET.
/// </summary>
public interface ICurrentUser
{
    bool IsAuthenticated { get; }

    /// <summary>The <c>sub</c> claim, or null when the request is anonymous.</summary>
    string? Subject { get; }

    /// <summary>An actor string for audit rows: <c>preferred_username</c>, then <c>name</c>, then
    /// <c>email</c>. The stable handle wins here, which is the opposite of what
    /// <see cref="ExternalUserProfile.DisplayName"/> wants, on purpose.</summary>
    string? Name { get; }

    /// <summary>
    /// The local user row for this request, created on first sight. Memoised per request, so
    /// calling it repeatedly costs one lookup. Throws when the request is anonymous, and when
    /// provisioning is not registered.
    /// </summary>
    Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default);
}
