using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

internal sealed class FakeTrustedDeviceStore : ITrustedDeviceStore
{
    internal List<ToamaisutaaTrustedDevice> Devices { get; } = [];

    public Task<ToamaisutaaTrustedDevice?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        Task.FromResult(Devices.FirstOrDefault(device => device.TokenHash == tokenHash));

    public Task<IReadOnlyList<ToamaisutaaTrustedDevice>> ListActiveAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ToamaisutaaTrustedDevice>>(
            [.. Devices.Where(device => device.UserId == userId && device.RotatedAt is null && device.RevokedAt is null)]);

    public Task CreateAsync(ToamaisutaaTrustedDevice device, CancellationToken cancellationToken = default)
    {
        Devices.Add(device);
        return Task.CompletedTask;
    }

    public Task MarkRotatedAsync(Guid deviceId, DateTimeOffset rotatedAt, CancellationToken cancellationToken = default)
    {
        var device = Devices.FirstOrDefault(entry => entry.Id == deviceId);

        if (device is not null)
        {
            device.RotatedAt = rotatedAt;
            device.LastUsedAt = rotatedAt;
        }

        return Task.CompletedTask;
    }

    public Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        foreach (var device in Devices.Where(entry => entry.FamilyId == familyId && entry.RevokedAt is null))
        {
            device.RevokedAt = revokedAt;
            device.RevokedReason = reason;
        }

        return Task.CompletedTask;
    }

    public Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var affected = Devices.Where(entry => entry.UserId == userId && entry.RevokedAt is null).ToList();

        foreach (var device in affected)
        {
            device.RevokedAt = revokedAt;
            device.RevokedReason = reason;
        }

        return Task.FromResult(affected.Count);
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        Task.FromResult(Devices.RemoveAll(device => device.ExpiresAt <= expiredBefore));
}
