namespace Toamaisutaa.Abstractions;

/// <summary>
/// Listing and revoking the sessions a user has open. A session here is a refresh family - the same
/// thing <c>toa_sid</c> names - so it survives every rotation and ends when the family does.
/// </summary>
public interface ISessionService
{
    /// <summary>
    /// Every live session, newest activity first.
    /// </summary>
    /// <remarks>
    /// <c>currentSessionId</c> is the caller's own <c>toa_sid</c>, marked by
    /// <see cref="SessionSummary.IsCurrent"/>. Null for a token this package did not issue.
    /// </remarks>
    Task<IReadOnlyList<SessionSummary>> ListAsync(
        Guid userId,
        Guid? currentSessionId = null,
        CancellationToken cancellationToken = default);

    /// <summary>False when the session does not exist or belongs to someone else - deliberately the
    /// same answer, so another account's session ids cannot be discovered.</summary>
    Task<bool> RevokeAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs out everywhere else: every live family except <paramref name="currentSessionId"/>.
    /// Returns how many were revoked.
    /// </summary>
    /// <remarks>
    /// Pass null to revoke every one.
    /// </remarks>
    Task<int> RevokeAllExceptAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken = default);
}

public sealed record SessionSummary
{
    /// <summary>The refresh family id, which survives rotation and is what <c>toa_sid</c> carries.
    /// Pass it back to revoke.</summary>
    public required Guid Id { get; init; }

    /// <summary>Raw and truncated, from the request that established the session.</summary>
    public string? UserAgent { get; init; }

    /// <summary>Null unless <c>LocalLogin:IpAddressStorage</c> says otherwise.</summary>
    public string? IpAddress { get; init; }

    /// <summary>When the family started. Rotation does not move it.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>When this session last signed in or refreshed.</summary>
    public required DateTimeOffset LastUsedAt { get; init; }

    /// <summary>
    /// When this session ends without further use: the sooner of the live token's own expiry and
    /// the family's absolute lifetime. Refreshing moves the first; nothing moves the second.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The RFC 8176 methods this session was established with, as replayed into <c>amr</c>.</summary>
    public required IReadOnlyList<string> AuthenticationMethods { get; init; }

    /// <summary>True for the session making the request.</summary>
    public required bool IsCurrent { get; init; }
}
