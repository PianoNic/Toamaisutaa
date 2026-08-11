using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Deletes refresh and reset tokens that are past their expiry. Opt-in, because a package should
/// not start doing background writes to someone's database without being asked - but offered,
/// because the alternative is a table nobody thinks about until it is enormous.
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

    private async Task CleanupAsync(CancellationToken cancellationToken)
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

        if (removedRefresh + removedReset + removedChallenges + removedDevices > 0)
        {
            logger.LogInformation(
                "Removed {RefreshTokens} expired refresh token(s), {ResetTokens} expired reset token(s), {Challenges} "
                + "expired two-factor challenge(s) and {Devices} expired trusted device row(s).",
                removedRefresh,
                removedReset,
                removedChallenges,
                removedDevices);
        }
    }
}
