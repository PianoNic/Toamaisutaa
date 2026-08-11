using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

internal sealed class EntityFrameworkTrustedDeviceStore<TContext>(TContext context) : ITrustedDeviceStore
    where TContext : DbContext
{
    public async Task<ToamaisutaaTrustedDevice?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .FirstOrDefaultAsync(device => device.TokenHash == tokenHash, cancellationToken);

    /// <summary>
    /// The live row of each family: not rotated, not revoked. Rotated rows stay in the table because
    /// reuse detection needs them, but they are not devices anybody has.
    /// </summary>
    public async Task<IReadOnlyList<ToamaisutaaTrustedDevice>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .Where(device => device.UserId == userId && device.RotatedAt == null && device.RevokedAt == null)
            .ToListAsync(cancellationToken);

    public async Task CreateAsync(ToamaisutaaTrustedDevice device, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaTrustedDevice>().Add(device);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task MarkRotatedAsync(Guid deviceId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .Where(device => device.Id == deviceId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(device => device.RotatedAt, rotatedAt)
                    .SetProperty(device => device.LastUsedAt, rotatedAt),
                cancellationToken);

    public async Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .Where(device => device.FamilyId == familyId && device.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(device => device.RevokedAt, revokedAt)
                    .SetProperty(device => device.RevokedReason, reason),
                cancellationToken);

    public async Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .Where(device => device.UserId == userId && device.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(device => device.RevokedAt, revokedAt)
                    .SetProperty(device => device.RevokedReason, reason),
                cancellationToken);

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTrustedDevice>()
            .Where(device => device.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
