using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class TrustedDeviceService(
    ITrustedDeviceStore devices,
    AuthenticationEventPublisher events,
    TimeProvider timeProvider,
    ILogger<TrustedDeviceService> logger) : ITrustedDeviceService
{
    /// <summary>Identifies the caller's own device; never return it or log it.</summary>
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

        // Scoped to this user's own list, so another user's device id is indistinguishable from one
        // that never existed.
        if (!active.Any(device => device.FamilyId == deviceId))
            return false;

        var now = timeProvider.GetUtcNow();

        await devices.RevokeFamilyAsync(deviceId, "revoked-by-user", now, cancellationToken);
        logger.LogInformation("User {UserId} revoked trusted device {FamilyId}.", userId, deviceId);

        await events.PublishAsync(
            new TrustedDeviceRevoked
            {
                OccurredAt = now,
                UserId = userId,
                DeviceId = deviceId,
                Reason = "revoked-by-user",
            },
            cancellationToken);

        return true;
    }

    public async Task<int> RevokeAllAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        var revoked = await devices.RevokeAllForUserAsync(userId, "revoked-by-user", now, cancellationToken);
        logger.LogInformation("User {UserId} revoked every trusted device: {Count} row(s).", userId, revoked);

        if (revoked > 0)
        {
            await events.PublishAsync(
                new TrustedDeviceRevoked { OccurredAt = now, UserId = userId, Reason = "revoked-by-user" },
                cancellationToken);
        }

        return revoked;
    }
}
