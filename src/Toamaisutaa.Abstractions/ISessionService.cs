namespace Toamaisutaa.Abstractions;

/// <summary>
/// Listing and revoking the sessions a user has open. A session here is a refresh family - the same
/// thing <c>toa_sid</c> names - so it survives every rotation and ends when the family does.
/// </summary>
/// <remarks>
/// Public for the reason <see cref="ITrustedDeviceService"/> is: an application that wants its own
/// shape, its own route or its own audit trail around "sign out everywhere" injects this instead of
/// mapping the endpoints, and there is no other way to reach a refresh family without writing a
/// store query by hand.
/// </remarks>
public interface ISessionService
{
    /// <summary>
    /// Every live session, newest activity first.
    /// </summary>
    /// <remarks>
    /// <c>currentSessionId</c> is the caller's own <c>toa_sid</c>, which comes back as
    /// <see cref="SessionSummary.IsCurrent"/> on the matching entry. Passed in rather than read
    /// here, so nothing below the web layer learns what an HTTP request is. Null for a caller
    /// holding a token this package did not issue, and then no entry is current.
    /// </remarks>
    Task<IReadOnlyList<SessionSummary>> ListAsync(
        Guid userId,
        Guid? currentSessionId = null,
        CancellationToken cancellationToken = default);

    /// <summary>False when the session does not exist or belongs to someone else - which are the
    /// same answer, so that this cannot be used to discover another account's session ids.</summary>
    Task<bool> RevokeAsync(Guid userId, Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs out everywhere else: every live family except <paramref name="currentSessionId"/>.
    /// Returns how many were revoked.
    /// </summary>
    /// <remarks>
    /// Keeping the caller signed in is the point. Revoking their own session too would log them out
    /// of the page they clicked the button on, and the only way back is the login form - which is
    /// what someone reaches for this precisely to avoid. Pass null to revoke every one.
    /// </remarks>
    Task<int> RevokeAllExceptAsync(Guid userId, Guid? currentSessionId, CancellationToken cancellationToken = default);
}

public sealed record SessionSummary
{
    /// <summary>The refresh family id, which survives rotation and is what <c>toa_sid</c> carries.
    /// Pass it back to revoke.</summary>
    public required Guid Id { get; init; }

    /// <summary>Raw and truncated, from the request that established the session. Deliberately not
    /// parsed into a friendly name - that is either a dependency or a lookup table that rots.</summary>
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

    /// <summary>The RFC 8176 methods this session was established with, as they are replayed into
    /// <c>amr</c>. <c>mfa</c> here is how a list says which sessions proved a second factor.</summary>
    public required IReadOnlyList<string> AuthenticationMethods { get; init; }

    /// <summary>True for the session making the request, so a list can say "this device" rather than
    /// inviting somebody to sign out of the page they are looking at.</summary>
    public required bool IsCurrent { get; init; }
}
