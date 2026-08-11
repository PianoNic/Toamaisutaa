using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class TrustedDeviceService(
    ITrustedDeviceStore devices,
    TimeProvider timeProvider,
    ILogger<TrustedDeviceService> logger) : ITrustedDeviceService
{
    /// <summary>
    /// Set by the endpoint from the request's own device token, so the list can mark one entry as
    /// "this device". Never returned to the caller and never logged.
    /// </summary>
    internal string? CurrentDeviceTokenHash { get; set; }

    public async Task<IReadOnlyList<TrustedDeviceSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var active = await devices.ListActiveAsync(userId, cancellationToken);

        return [.. active
            .OrderByDescending(device => device.LastUsedAt)
            .Select(device => new TrustedDeviceSummary
            {
                Id = device.FamilyId,
                Label = device.Label,
                UserAgent = device.UserAgent,
                IpAddress = device.IpAddress,
                CreatedAt = device.FamilyStartedAt,
                LastUsedAt = device.LastUsedAt,
                ExpiresAt = device.ExpiresAt,
                IsCurrent = CurrentDeviceTokenHash is not null
                    && string.Equals(device.TokenHash, CurrentDeviceTokenHash, StringComparison.Ordinal),
            })];
    }

    public async Task<bool> RevokeAsync(Guid userId, Guid deviceId, CancellationToken cancellationToken = default)
    {
        var active = await devices.ListActiveAsync(userId, cancellationToken);

        // Scoped to this user's own list, so a device id belonging to someone else is
        // indistinguishable from one that never existed.
        if (!active.Any(device => device.FamilyId == deviceId))
            return false;

        await devices.RevokeFamilyAsync(deviceId, "revoked-by-user", timeProvider.GetUtcNow(), cancellationToken);
        logger.LogInformation("User {UserId} revoked trusted device {FamilyId}.", userId, deviceId);

        return true;
    }

    public async Task<int> RevokeAllAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var revoked = await devices.RevokeAllForUserAsync(userId, "revoked-by-user", timeProvider.GetUtcNow(), cancellationToken);
        logger.LogInformation("User {UserId} revoked every trusted device: {Count} row(s).", userId, revoked);

        return revoked;
    }
}
