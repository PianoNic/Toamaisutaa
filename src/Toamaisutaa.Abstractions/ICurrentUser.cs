namespace Toamaisutaa.Abstractions;

/// <summary>
/// What application code injects to find out who is calling. Deliberately not HTTP-shaped, so a
/// domain or application layer can depend on it without referencing ASP.NET.
/// </summary>
/// <remarks>
/// <see cref="Roles"/>, <see cref="IsInRole"/> and <see cref="FindClaim"/> carry a default that
/// answers empty rather than being abstract. An implementation with no claims to read - a worker,
/// a test double - is then correct as written, and one written before these existed keeps
/// compiling.
/// </remarks>
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

    /// <summary>
    /// Membership as the token states it, read from the claim <c>Oidc:RoleClaim</c> names and from
    /// the role claim type the principal's own identities name - which is what <c>RequireRole</c>
    /// reads, so the two agree. Empty on an anonymous request. A read of the token, not an
    /// authorization decision: it answers
    /// "what does this caller carry", while <c>[Authorize]</c> answers "may this caller in".
    /// </summary>
    IReadOnlyList<string> Roles => [];

    /// <summary>Whether <see cref="Roles"/> contains <paramref name="role"/>, compared ordinally -
    /// the same comparison <c>RequireRole</c> makes.</summary>
    bool IsInRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

    /// <summary>The first non-empty value of <paramref name="type"/>, or null. Raw JWT claim types,
    /// because inbound claim mapping is off - <c>tenant_id</c>, not the WS-Federation URI.</summary>
    string? FindClaim(string type) => null;
}
