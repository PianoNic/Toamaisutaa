using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Stores are resolved through the provider rather than the constructor so password login without
/// device trust registered does not crash at the first sign-in.
/// </summary>
internal sealed class TrustedDeviceGate(
    IServiceProvider provider,
    AuthenticationEventPublisher events,
    IOptions<ToamaisutaaTrustedDeviceOptions> options,
    ILogger<TrustedDeviceGate> logger)
{
    internal async Task<DeviceTrustResult> TryRedeemAsync(
        ToamaisutaaUser user,
        string? deviceToken,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(deviceToken))
            return DeviceTrustResult.NotTrusted;

        var devices = provider.GetService<ITrustedDeviceStore>();
        if (devices is null)
            return DeviceTrustResult.NotTrusted;

        var stored = await devices.FindByHashAsync(SecureTokens.HashToken(deviceToken), cancellationToken);

        if (stored is null || stored.UserId != user.Id)
            return DeviceTrustResult.NotTrusted;

        if (stored.RotatedAt is not null)
        {
            // Two parties hold the chain and there is no way to tell which is the owner, so neither
            // keeps it.
            logger.LogWarning(
                "Trusted-device token reuse detected for user {UserId}. Device {DeviceId} was already rotated at "
                + "{RotatedAt}; revoking family {FamilyId}. Treat this as a possible captured token.",
                stored.UserId,
                stored.Id,
                stored.RotatedAt,
                stored.FamilyId);

            await RevokeFamilyAsync(devices, stored, "device-token-reuse", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        if (stored.RevokedAt is not null)
            return DeviceTrustResult.NotTrusted;

        // Absolute from when the family started, so a device used every week still expires.
        if (stored.ExpiresAt <= now || stored.FamilyStartedAt + options.Value.Lifetime <= now)
        {
            logger.LogInformation(
                "Trusted device {FamilyId} for user {UserId} reached its absolute lifetime; a live second factor is required.",
                stored.FamilyId,
                stored.UserId);

            await RevokeFamilyAsync(devices, stored, "absolute-lifetime-reached", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        // This is what makes every credential change revoke device trust without each remembering to.
        if (!string.Equals(stored.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Trusted device {FamilyId} for user {UserId} was established before a credential changed; refusing it "
                + "and requiring a second factor.",
                stored.FamilyId,
                stored.UserId);

            await RevokeFamilyAsync(devices, stored, "security-stamp-changed", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        // Guards against an enrolment removed without bumping the stamp.
        var enrolments = provider.GetService<ITwoFactorStore>();
        if (enrolments is not null)
        {
            var enrolment = await enrolments.FindAsync(user.Id, cancellationToken);

            if (enrolment is not { ConfirmedAt: not null })
            {
                await RevokeFamilyAsync(devices, stored, "no-enrolment", now, cancellationToken);
                return DeviceTrustResult.NotTrusted;
            }
        }

        // Conditional write: the loser of a concurrent exchange presented a token already being
        // rotated, which is reuse.
        if (!await devices.MarkRotatedAsync(stored.Id, now, cancellationToken))
        {
            logger.LogWarning(
                "Trusted-device token reuse detected for user {UserId}. Device {DeviceId} was exchanged by another "
                + "request first; revoking family {FamilyId}. Treat this as a possible captured token.",
                stored.UserId,
                stored.Id,
                stored.FamilyId);

            await RevokeFamilyAsync(devices, stored, "device-token-reuse", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        var rotated = SecureTokens.Create();

        await devices.CreateAsync(
            new ToamaisutaaTrustedDevice
            {
                Id = Guid.CreateVersion7(now),
                FamilyId = stored.FamilyId,
                UserId = stored.UserId,
                TokenHash = SecureTokens.HashToken(rotated),
                SecurityStamp = user.SecurityStamp,

                // Carried, never refreshed: this is toa_2fa_at, and moving it would make every
                // sign-in look freshly verified.
                SecondFactorAt = stored.SecondFactorAt,

                Label = stored.Label,
                UserAgent = stored.UserAgent,
                IpAddress = stored.IpAddress,
                CreatedAt = now,

                // Carried, or each presentation would buy another full lifetime.
                FamilyStartedAt = stored.FamilyStartedAt,

                ExpiresAt = stored.FamilyStartedAt + options.Value.Lifetime,
                LastUsedAt = now,
            },
            cancellationToken);

        logger.LogInformation("Second factor satisfied from trusted device {FamilyId} for user {UserId}.", stored.FamilyId, stored.UserId);

        return new DeviceTrustResult
        {
            Trusted = true,
            SecondFactorAt = stored.SecondFactorAt,
            RotatedToken = new TrustedDeviceToken(
                rotated,
                (int)Math.Max(0, (stored.FamilyStartedAt + options.Value.Lifetime - now).TotalSeconds)),
        };
    }

    /// <summary>
    /// Call only after a live second factor, never from a device-trusted sign-in, or a family
    /// renews itself forever.
    /// </summary>
    internal async Task<TrustedDeviceToken?> IssueAsync(
        ToamaisutaaUser user,
        TwoFactorSignInRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!request.RememberDevice)
            return null;

        var devices = provider.GetService<ITrustedDeviceStore>();
        if (devices is null)
        {
            logger.LogWarning(
                "User {UserId} asked to be remembered but no ITrustedDeviceStore is registered. Call "
                + "AddToamaisutaaTrustedDevices(...) or stop sending rememberDevice.",
                user.Id);

            return null;
        }

        var settings = options.Value;
        var raw = SecureTokens.Create();
        var family = Guid.CreateVersion7(now);
        var label = ClientMetadata.Truncate(request.DeviceLabel, 128);

        await devices.CreateAsync(
            new ToamaisutaaTrustedDevice
            {
                Id = Guid.CreateVersion7(now),
                FamilyId = family,
                UserId = user.Id,
                TokenHash = SecureTokens.HashToken(raw),
                SecurityStamp = user.SecurityStamp,
                SecondFactorAt = now,
                Label = label,
                UserAgent = ClientMetadata.Truncate(request.UserAgent, ClientMetadata.UserAgentLength),
                IpAddress = ClientMetadata.ResolveAddress(request.IpAddress, settings.IpAddressStorage),
                CreatedAt = now,
                FamilyStartedAt = now,
                ExpiresAt = now + settings.Lifetime,
                LastUsedAt = now,
            },
            cancellationToken);

        await EnforceDeviceCapAsync(devices, user.Id, now, cancellationToken);

        await events.PublishAsync(
            new TrustedDeviceAdded
            {
                OccurredAt = now,
                UserId = user.Id,
                DeviceId = family,
                Label = label,
            },
            cancellationToken);

        logger.LogInformation("User {UserId} trusted a new device; it expires at {ExpiresAt}.", user.Id, now + settings.Lifetime);

        return new TrustedDeviceToken(raw, (int)settings.Lifetime.TotalSeconds);
    }

    /// <summary>
    /// For the two places the security stamp cannot do the job: redeeming a recovery code, and
    /// detecting refresh-token reuse.
    /// </summary>
    internal async Task RevokeAllAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var devices = provider.GetService<ITrustedDeviceStore>();
        if (devices is null)
            return;

        var revoked = await devices.RevokeAllForUserAsync(userId, reason, now, cancellationToken);

        if (revoked == 0)
            return;

        logger.LogWarning("Revoked {Count} trusted device(s) for user {UserId}: {Reason}.", revoked, userId, reason);

        await events.PublishAsync(
            new TrustedDeviceRevoked { OccurredAt = now, UserId = userId, Reason = reason },
            cancellationToken);
    }

    private async Task EnforceDeviceCapAsync(ITrustedDeviceStore devices, Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var cap = options.Value.MaxDevicesPerUser;
        if (cap <= 0)
            return;

        var active = await devices.ListActiveAsync(userId, cancellationToken);
        if (active.Count <= cap)
            return;

        foreach (var stale in active.OrderByDescending(device => device.FamilyStartedAt).Skip(cap))
        {
            await RevokeFamilyAsync(devices, stale, "device-limit-reached", now, cancellationToken);
            logger.LogInformation("Revoked trusted device {FamilyId} for user {UserId}: the per-user limit was reached.", stale.FamilyId, userId);
        }
    }

    private async Task RevokeFamilyAsync(
        ITrustedDeviceStore devices,
        ToamaisutaaTrustedDevice stored,
        string reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await devices.RevokeFamilyAsync(stored.FamilyId, reason, now, cancellationToken);

        await events.PublishAsync(
            new TrustedDeviceRevoked
            {
                OccurredAt = now,
                UserId = stored.UserId,
                DeviceId = stored.FamilyId,
                Reason = reason,
            },
            cancellationToken);
    }
}

internal readonly record struct DeviceTrustResult
{
    internal bool Trusted { get; init; }

    internal DateTimeOffset SecondFactorAt { get; init; }

    internal TrustedDeviceToken? RotatedToken { get; init; }

    internal static DeviceTrustResult NotTrusted => new() { Trusted = false };
}
