using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// What the sign-in path is allowed to know about trusted devices.
/// </summary>
/// <remarks>
/// Resolved through the provider rather than the constructor, for the same reason as
/// <see cref="TwoFactorGate"/>: password login works with no device trust registered, and a
/// constructor dependency would turn "did not call AddToamaisutaaTrustedDevices" into a crash at the
/// first sign-in. Absent, every method here answers no.
/// </remarks>
internal sealed class TrustedDeviceGate(
    IServiceProvider provider,
    IOptions<ToamaisutaaTrustedDeviceOptions> options,
    ILogger<TrustedDeviceGate> logger)
{
    /// <summary>
    /// Whether this device token stands in for a live second factor.
    /// </summary>
    /// <remarks>
    /// Every rejection path deletes the row rather than leaving it: a trust that failed its stamp
    /// check is never going to pass one, and leaving it would show the user a device in their list
    /// that does nothing.
    /// </remarks>
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
            // Already exchanged, so two parties hold the chain and one of them is not the account
            // owner. There is no way to tell which, so neither keeps it.
            logger.LogWarning(
                "Trusted-device token reuse detected for user {UserId}. Device {DeviceId} was already rotated at "
                + "{RotatedAt}; revoking family {FamilyId}. Treat this as a possible captured token.",
                stored.UserId,
                stored.Id,
                stored.RotatedAt,
                stored.FamilyId);

            await devices.RevokeFamilyAsync(stored.FamilyId, "device-token-reuse", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        if (stored.RevokedAt is not null)
            return DeviceTrustResult.NotTrusted;

        // Absolute, from when the family started. Rotation never moved it, so a device used every
        // week still lands here eventually.
        if (stored.ExpiresAt <= now || stored.FamilyStartedAt + options.Value.Lifetime <= now)
        {
            logger.LogInformation(
                "Trusted device {FamilyId} for user {UserId} reached its absolute lifetime; a live second factor is required.",
                stored.FamilyId,
                stored.UserId);

            await devices.RevokeFamilyAsync(stored.FamilyId, "absolute-lifetime-reached", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        // The check that makes every credential change revoke device trust without each of them
        // having to remember to.
        if (!string.Equals(stored.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Trusted device {FamilyId} for user {UserId} was established before a credential changed; refusing it "
                + "and requiring a second factor.",
                stored.FamilyId,
                stored.UserId);

            await devices.RevokeFamilyAsync(stored.FamilyId, "security-stamp-changed", now, cancellationToken);
            return DeviceTrustResult.NotTrusted;
        }

        // The enrolment can be gone without the stamp moving only if something revoked it without
        // bumping - belt and braces, and cheap.
        var enrolments = provider.GetService<ITwoFactorStore>();
        if (enrolments is not null)
        {
            var enrolment = await enrolments.FindAsync(user.Id, cancellationToken);

            if (enrolment is not { ConfirmedAt: not null })
            {
                await devices.RevokeFamilyAsync(stored.FamilyId, "no-enrolment", now, cancellationToken);
                return DeviceTrustResult.NotTrusted;
            }
        }

        await devices.MarkRotatedAsync(stored.Id, now, cancellationToken);

        var rotated = SecureTokens.Create();

        await devices.CreateAsync(
            new ToamaisutaaTrustedDevice
            {
                Id = Guid.CreateVersion7(now),
                FamilyId = stored.FamilyId,
                UserId = stored.UserId,
                TokenHash = SecureTokens.HashToken(rotated),
                SecurityStamp = user.SecurityStamp,

                // Carried, never refreshed. This is what a device-trusted token reports as
                // toa_2fa_at, and moving it here would make every sign-in look freshly verified.
                SecondFactorAt = stored.SecondFactorAt,

                Label = stored.Label,
                UserAgent = stored.UserAgent,
                IpAddress = stored.IpAddress,
                CreatedAt = now,

                // Likewise carried. If this moved, presenting a device token would buy another full
                // lifetime and the absolute limit would never be reached.
                FamilyStartedAt = stored.FamilyStartedAt,

                ExpiresAt = stored.FamilyStartedAt + options.Value.Lifetime,
                LastUsedAt = now,
            },
            cancellationToken);

        logger.LogInformation("Second factor satisfied from trusted device {FamilyId} for user {UserId}.", stored.FamilyId, stored.UserId);

        return new DeviceTrustResult
        {
            Trusted = true,
            FamilyId = stored.FamilyId,
            SecondFactorAt = stored.SecondFactorAt,
            RotatedToken = new TrustedDeviceToken(
                rotated,
                (int)Math.Max(0, (stored.FamilyStartedAt + options.Value.Lifetime - now).TotalSeconds)),
        };
    }

    /// <summary>
    /// Starts a new family. Called only after a <b>live</b> second factor - never from a
    /// device-trusted sign-in, which is what stops a family renewing itself forever.
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

        await devices.CreateAsync(
            new ToamaisutaaTrustedDevice
            {
                Id = Guid.CreateVersion7(now),
                FamilyId = Guid.CreateVersion7(now),
                UserId = user.Id,
                TokenHash = SecureTokens.HashToken(raw),
                SecurityStamp = user.SecurityStamp,
                SecondFactorAt = now,
                Label = Truncate(request.DeviceLabel, 128),
                UserAgent = Truncate(request.UserAgent, 256),
                IpAddress = ResolveAddress(request.IpAddress, settings.IpAddressStorage),
                CreatedAt = now,
                FamilyStartedAt = now,
                ExpiresAt = now + settings.Lifetime,
                LastUsedAt = now,
            },
            cancellationToken);

        await EnforceDeviceCapAsync(devices, user.Id, now, cancellationToken);

        logger.LogInformation("User {UserId} trusted a new device; it expires at {ExpiresAt}.", user.Id, now + settings.Lifetime);

        return new TrustedDeviceToken(raw, (int)settings.Lifetime.TotalSeconds);
    }

    /// <summary>
    /// Explicit revocation, for the two places the security stamp cannot do the job: redeeming a
    /// recovery code, and detecting refresh-token reuse.
    /// </summary>
    internal async Task RevokeAllAsync(Guid userId, string reason, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var devices = provider.GetService<ITrustedDeviceStore>();
        if (devices is null)
            return;

        var revoked = await devices.RevokeAllForUserAsync(userId, reason, now, cancellationToken);

        if (revoked > 0)
            logger.LogWarning("Revoked {Count} trusted device(s) for user {UserId}: {Reason}.", revoked, userId, reason);
    }

    /// <summary>Oldest family out. Every live device is a second factor somebody is not being asked
    /// for, and one accumulates per browser otherwise.</summary>
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
            await devices.RevokeFamilyAsync(stale.FamilyId, "device-limit-reached", now, cancellationToken);
            logger.LogInformation("Revoked trusted device {FamilyId} for user {UserId}: the per-user limit was reached.", stale.FamilyId, userId);
        }
    }

    private static string? Truncate(string? value, int length) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= length ? value : value[..length];

    /// <summary>
    /// Truncation keeps the network and drops the host: /24 for IPv4, /48 for IPv6. Enough to say
    /// "somewhere else" without storing something that identifies a person.
    /// </summary>
    private static string? ResolveAddress(string? address, IpAddressStorage storage)
    {
        if (storage == IpAddressStorage.None || string.IsNullOrWhiteSpace(address))
            return null;

        if (storage == IpAddressStorage.Full)
            return Truncate(address, 64);

        if (!System.Net.IPAddress.TryParse(address, out var parsed))
            return null;

        var bytes = parsed.GetAddressBytes();

        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            bytes[3] = 0;
            return new System.Net.IPAddress(bytes).ToString() + "/24";
        }

        for (var i = 6; i < bytes.Length; i++)
            bytes[i] = 0;

        return new System.Net.IPAddress(bytes).ToString() + "/48";
    }
}

internal readonly record struct DeviceTrustResult
{
    internal bool Trusted { get; init; }

    internal Guid FamilyId { get; init; }

    internal DateTimeOffset SecondFactorAt { get; init; }

    internal TrustedDeviceToken? RotatedToken { get; init; }

    internal static DeviceTrustResult NotTrusted => new() { Trusted = false };
}
