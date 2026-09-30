using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal sealed class TokenCleanupService(
    IServiceScopeFactory scopeFactory,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<TokenCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.Value.TokenCleanupInterval, timeProvider);

        do
        {
            try
            {
                await CleanupAsync(stoppingToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogWarning(exception, "Expired-token cleanup failed. Trying again next interval.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>
    /// Refresh rows are kept until their family is past its absolute lifetime, because a rotated row
    /// is the evidence reuse detection needs to revoke the family when a stolen token is replayed.
    /// </summary>
    internal static DateTimeOffset RefreshCutoff(DateTimeOffset now, ToamaisutaaLocalLoginOptions settings)
    {
        var margin = settings.RefreshTokenAbsoluteLifetime - settings.RefreshTokenLifetime;
        return margin > TimeSpan.Zero ? now - margin : now;
    }

    internal async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();

        var now = timeProvider.GetUtcNow();
        var refreshTokens = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
        var resetTokens = scope.ServiceProvider.GetRequiredService<IPasswordResetTokenStore>();

        var removedRefresh = await refreshTokens.DeleteExpiredAsync(RefreshCutoff(now, options.Value), cancellationToken);
        var removedReset = await resetTokens.DeleteExpiredAsync(now, cancellationToken);

        // Optional stores: this service is registered on its own and must not require the features.
        var challenges = scope.ServiceProvider.GetService<ITwoFactorChallengeStore>();
        var removedChallenges = challenges is null ? 0 : await challenges.DeleteExpiredAsync(now, cancellationToken);

        var devices = scope.ServiceProvider.GetService<ITrustedDeviceStore>();
        var removedDevices = devices is null ? 0 : await devices.DeleteExpiredAsync(now, cancellationToken);

        var invitations = scope.ServiceProvider.GetService<IInvitationTokenStore>();
        var removedInvitations = invitations is null ? 0 : await invitations.DeleteExpiredAsync(now, cancellationToken);

        var verifications = scope.ServiceProvider.GetService<IEmailVerificationTokenStore>();
        var removedVerifications = verifications is null ? 0 : await verifications.DeleteExpiredAsync(now, cancellationToken);

        var magicLinks = scope.ServiceProvider.GetService<IMagicLinkTokenStore>();
        var removedMagicLinks = magicLinks is null ? 0 : await magicLinks.DeleteExpiredAsync(now, cancellationToken);

        var passkeyChallenges = scope.ServiceProvider.GetService<IPasskeyChallengeStore>();
        var removedPasskeyChallenges = passkeyChallenges is null ? 0 : await passkeyChallenges.DeleteExpiredAsync(now, cancellationToken);

        var removed = removedRefresh + removedReset + removedChallenges + removedDevices + removedInvitations
            + removedVerifications + removedMagicLinks + removedPasskeyChallenges;

        if (removed > 0)
        {
            logger.LogInformation(
                "Removed {RefreshTokens} expired refresh token(s), {ResetTokens} expired reset token(s), {Challenges} "
                + "expired two-factor challenge(s), {Devices} expired trusted device row(s), {Invitations} expired "
                + "invitation token(s), {Verifications} expired email verification token(s), {MagicLinks} expired "
                + "magic-link token(s) and {PasskeyChallenges} expired passkey challenge(s).",
                removedRefresh,
                removedReset,
                removedChallenges,
                removedDevices,
                removedInvitations,
                removedVerifications,
                removedMagicLinks,
                removedPasskeyChallenges);
        }
    }
}
