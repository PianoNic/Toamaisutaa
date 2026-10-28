using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkExternalLoginRequestStore<TContext>(TContext context) : IExternalLoginRequestStore
    where TContext : DbContext
{
    public async Task CreateAsync(ToamaisutaaExternalLoginRequest request, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaExternalLoginRequest>().Add(request);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaExternalLoginRequest?> FindByStateHashAsync(string stateHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .AsNoTracking()
            .FirstOrDefaultAsync(request => request.StateHash == stateHash, cancellationToken);

    public async Task<bool> MarkStateConsumedAsync(Guid requestId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .Where(request => request.Id == requestId && request.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(request => request.ConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task SetExchangeAsync(
        Guid requestId,
        string exchangeCodeHash,
        Guid userId,
        string securityStamp,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .Where(request => request.Id == requestId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(request => request.ExchangeCodeHash, exchangeCodeHash)
                    .SetProperty(request => request.UserId, userId)
                    .SetProperty(request => request.SecurityStamp, securityStamp)
                    .SetProperty(request => request.ExpiresAt, expiresAt),
                cancellationToken);

    public async Task<ToamaisutaaExternalLoginRequest?> FindByExchangeCodeHashAsync(string exchangeCodeHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .AsNoTracking()
            .FirstOrDefaultAsync(request => request.ExchangeCodeHash == exchangeCodeHash, cancellationToken);

    public async Task<bool> MarkExchangeConsumedAsync(Guid requestId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .Where(request => request.Id == requestId && request.ExchangeConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(request => request.ExchangeConsumedAt, consumedAt), cancellationToken) == 1;

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLoginRequest>()
            .Where(request => request.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
