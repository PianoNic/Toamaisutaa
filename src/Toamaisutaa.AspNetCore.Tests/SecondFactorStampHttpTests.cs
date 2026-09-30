using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

public class SecondFactorStampHttpTests
{
    /// <summary>
    /// The challenge's stamp was checked, then the user read again to mint with. Under a no-tracking
    /// context that read saw a reset landing in between, and the session carried the reset's stamp,
    /// so it survived the reset meant to end it.
    /// </summary>
    [Test]
    public async Task A_reset_while_the_code_is_checked_is_not_handed_to_the_session()
    {
        var reset = new ResetWhileVerifying();
        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.ConfigureDbContext<ToamaisutaaDbContext>(db => db.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking));
            reset.Register(services);
        });

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = (await account.LoginAsync()).Json().Result.String("challenge")!;
        app.Time.AdvanceToNextTotpStep();

        reset.Services = app.Services;
        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(reset.Reset).IsTrue();
        await Assert.That(verify.StatusCode).IsNotEqualTo(HttpStatusCode.OK);
        await Assert.That((await verify.Json()).Has("access_token")).IsFalse();
    }

    private sealed class ResetWhileVerifying
    {
        internal IServiceProvider? Services;

        internal bool Reset;

        internal void Register(IServiceCollection services) =>
            services.Decorate<ITwoFactorStore>(inner => new Store(this, inner));

        private sealed class Store(ResetWhileVerifying owner, ITwoFactorStore inner) : ITwoFactorStore
        {
            public Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.FindAsync(userId, cancellationToken);

            public Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default) =>
                inner.UpsertAsync(enrolment, cancellationToken);

            public Task<bool> ReplacePendingAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default) =>
                inner.ReplacePendingAsync(enrolment, cancellationToken);

            public Task<bool> RewrapSecretAsync(Guid userId, string expectedKeyVersion, byte[] secretCiphertext, byte[] secretNonce, byte[] secretTag, string keyVersion, DateTimeOffset updatedAt, CancellationToken cancellationToken = default) =>
                inner.RewrapSecretAsync(userId, expectedKeyVersion, secretCiphertext, secretNonce, secretTag, keyVersion, updatedAt, cancellationToken);

            public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.DeleteAsync(userId, cancellationToken);

            // After the gate checked the challenge's stamp and before the sign-in reads the user again.
            public async Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default)
            {
                var recorded = await inner.RecordUsedStepAsync(userId, step, cancellationToken);

                if (recorded && owner.Services is { } services)
                {
                    owner.Services = null;

                    await using var scope = services.CreateAsyncScope();
                    await scope.ServiceProvider.GetRequiredService<IUserStore>()
                        .UpdateSecurityStampAsync(userId, Guid.NewGuid().ToString("N"), cancellationToken);

                    owner.Reset = true;
                }

                return recorded;
            }

            public Task<bool> UpdateFailedAttemptsAsync(Guid userId, int expectedFailedAttemptCount, DateTimeOffset? expectedFirstFailedAttemptAt, DateTimeOffset? expectedLockedOutUntil, int failedAttemptCount, DateTimeOffset? firstFailedAttemptAt, DateTimeOffset? lockedOutUntil, CancellationToken cancellationToken = default) =>
                inner.UpdateFailedAttemptsAsync(userId, expectedFailedAttemptCount, expectedFirstFailedAttemptAt, expectedLockedOutUntil, failedAttemptCount, firstFailedAttemptAt, lockedOutUntil, cancellationToken);
        }
    }
}
