namespace Toamaisutaa.Abstractions;

public interface IInvitationTokenStore
{
    Task CreateAsync(ToamaisutaaInvitationToken token, CancellationToken cancellationToken = default);

    Task<ToamaisutaaInvitationToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Spends the token in one conditional write. True only when this call spent it; false
    /// when another request already had. The flow acts on nothing until this says true.</summary>
    Task<bool> MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);

    /// <summary>Spends every unused invitation for the user. Called when the same address is invited
    /// again, so only the newest link works, and when an invitation is revoked.</summary>
    Task InvalidateAllForUserAsync(Guid userId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// The newest invitation to <paramref name="normalizedEmail"/> that is neither spent nor expired,
    /// or null. A user row is never assumed to be a reservation from its shape, because an account an
    /// identity provider owns has the same shape. Rows written before 0.8.0 have no
    /// <see cref="ToamaisutaaInvitationToken.NormalizedEmail"/> and must be matched on their user row's
    /// address, or revoking one reports it gone while its link still works.
    /// </summary>
    Task<ToamaisutaaInvitationToken?> FindOpenByEmailAsync(string normalizedEmail, DateTimeOffset now, CancellationToken cancellationToken = default);
}
