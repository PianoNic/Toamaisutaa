namespace Toamaisutaa.Abstractions;

public interface IInvitationTokenStore
{
    Task CreateAsync(ToamaisutaaInvitationToken token, CancellationToken cancellationToken = default);

    Task<ToamaisutaaInvitationToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    Task MarkConsumedAsync(Guid tokenId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
