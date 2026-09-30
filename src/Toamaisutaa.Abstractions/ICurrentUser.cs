namespace Toamaisutaa.Abstractions;

/// <summary>
/// What application code injects to find out who is calling, without referencing ASP.NET.
/// </summary>
public interface ICurrentUser
{
    bool IsAuthenticated { get; }

    /// <summary>The <c>sub</c> claim, or null when the request is anonymous.</summary>
    string? Subject { get; }

    /// <summary>An actor string for audit rows: <c>preferred_username</c>, then <c>name</c>, then
    /// <c>email</c>.</summary>
    string? Name { get; }

    /// <summary>
    /// The local user row for this request, created on first sight and memoised per request. Throws
    /// when the request is anonymous, and when provisioning is not registered.
    /// </summary>
    Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Membership as the token states it, read from the claim <c>Oidc:RoleClaim</c> names and from
    /// the principal's own role claim type, so it agrees with <c>RequireRole</c>. Empty on an
    /// anonymous request. Not an authorization decision.
    /// </summary>
    IReadOnlyList<string> Roles => [];

    /// <summary>Whether <see cref="Roles"/> contains <paramref name="role"/>, compared ordinally -
    /// the same comparison <c>RequireRole</c> makes.</summary>
    bool IsInRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

    /// <summary>The first non-empty value of <paramref name="type"/>, or null. Raw JWT claim types,
    /// because inbound claim mapping is off - <c>tenant_id</c>, not the WS-Federation URI.</summary>
    string? FindClaim(string type) => null;
}
