using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Deletes every expiring row this package writes - refresh, reset, invitation, email verification
/// and magic-link tokens, two-factor challenges and trusted devices - once it is past its expiry. Opt-in, because a
/// package should not start doing background writes to someone's database without being asked -
/// but offered, because the alternative is a table nobody thinks about until it is enormous.
/// </summary>
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
                // A sweep that fails is not worth taking the application down for; the rows are
                // still valid, just untidy.
                logger.LogWarning(exception, "Expired-token cleanup failed. Trying again next interval.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>One sweep. Internal rather than private because the host decides when
    /// <see cref="ExecuteAsync"/> first runs its body, which makes start-then-stop a race the tests
    /// lose; they run a sweep directly instead.</summary>
    internal async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();

        var now = timeProvider.GetUtcNow();
        var refreshTokens = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
        var resetTokens = scope.ServiceProvider.GetRequiredService<IPasswordResetTokenStore>();

        var removedRefresh = await refreshTokens.DeleteExpiredAsync(now, cancellationToken);
        var removedReset = await resetTokens.DeleteExpiredAsync(now, cancellationToken);

        // Optional, because two-factor is. Challenges expire in five minutes and every sign-in that
        // stops for one writes a row, so this is the fastest-growing of the three when it is on.
        var challenges = scope.ServiceProvider.GetService<ITwoFactorChallengeStore>();
        var removedChallenges = challenges is null ? 0 : await challenges.DeleteExpiredAsync(now, cancellationToken);

        var devices = scope.ServiceProvider.GetService<ITrustedDeviceStore>();
        var removedDevices = devices is null ? 0 : await devices.DeleteExpiredAsync(now, cancellationToken);

        // Optional for the same reason as the two above: this service is registered on its own and
        // does not require the password-login stores to be present.
        var invitations = scope.ServiceProvider.GetService<IInvitationTokenStore>();
        var removedInvitations = invitations is null ? 0 : await invitations.DeleteExpiredAsync(now, cancellationToken);

        var verifications = scope.ServiceProvider.GetService<IEmailVerificationTokenStore>();
        var removedVerifications = verifications is null ? 0 : await verifications.DeleteExpiredAsync(now, cancellationToken);

        var magicLinks = scope.ServiceProvider.GetService<IMagicLinkTokenStore>();
        var removedMagicLinks = magicLinks is null ? 0 : await magicLinks.DeleteExpiredAsync(now, cancellationToken);

        var removed = removedRefresh + removedReset + removedChallenges + removedDevices + removedInvitations
            + removedVerifications + removedMagicLinks;

        if (removed > 0)
        {
            logger.LogInformation(
                "Removed {RefreshTokens} expired refresh token(s), {ResetTokens} expired reset token(s), {Challenges} "
                + "expired two-factor challenge(s), {Devices} expired trusted device row(s), {Invitations} expired "
                + "invitation token(s), {Verifications} expired email verification token(s) and {MagicLinks} expired "
                + "magic-link token(s).",
                removedRefresh,
                removedReset,
                removedChallenges,
                removedDevices,
                removedInvitations,
                removedVerifications,
                removedMagicLinks);
        }
    }
}
