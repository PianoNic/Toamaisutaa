using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

public class SecretRewrapHttpTests
{
    private static readonly string OldKey = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray());
    private static readonly string CurrentKey = Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray());

    /// <summary>
    /// The rewrap after a code checks out wrote the whole row it read, so a later step recorded by
    /// another request in between went back to this one, and that later code worked twice.
    /// </summary>
    [Test]
    public async Task A_rewrap_does_not_move_the_used_step_back()
    {
        var laterStep = new RecordsALaterStep();
        await using var app = await TestApp.StartAsync(
            configure: settings =>
            {
                settings["TwoFactor:EncryptionKey"] = CurrentKey;
                settings["TwoFactor:EncryptionKeyVersion"] = "2";
                settings["TwoFactor:RetiredEncryptionKeys:1"] = OldKey;
            },
            configureServices: laterStep.Register);

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        await WrapUnderTheOldKeyAsync(app);

        laterStep.Armed = true;
        await account.SignInWithSecondFactorAsync();

        await Assert.That(laterStep.Recorded.HasValue).IsTrue();

        await using var scope = app.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>()
            .UserTwoFactors.AsNoTracking().SingleAsync();

        // Rewrapped, so the path under test actually ran.
        await Assert.That(stored.EncryptionKeyVersion).IsEqualTo("2:u");
        await Assert.That(stored.LastUsedStep).IsEqualTo(laterStep.Recorded);
    }

    /// <summary>
    /// The confirm keyed its write on the enrolment's UpdatedAt as read after the code was checked.
    /// The rewrap reloaded the row first, so a begin landing in between handed the confirm the new
    /// secret's UpdatedAt, and a secret the code was never checked against was switched on.
    /// </summary>
    [Test]
    public async Task A_confirm_does_not_switch_on_a_secret_begun_while_its_code_was_checked()
    {
        var hook = new RecordsALaterStep();
        await using var app = await TestApp.StartAsync(
            configure: settings =>
            {
                settings["TwoFactor:EncryptionKey"] = CurrentKey;
                settings["TwoFactor:EncryptionKeyVersion"] = "2";
                settings["TwoFactor:RetiredEncryptionKeys:1"] = OldKey;
            },
            configureServices: hook.Register);

        var account = await Account.RegisterAsync(app);
        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        // Under a retired key, so the verifier rewraps and reloads the row before the confirm.
        await WrapUnderTheOldKeyAsync(app);

        var begunAgain = false;
        hook.AfterRecording = async () => begunAgain = (await app.Client.PostJson(
            "/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken)).IsSuccessStatusCode;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, account.AccessToken);

        await Assert.That(begunAgain).IsTrue();
        await Assert.That(confirm.StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        await using var scope = app.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>()
            .UserTwoFactors.AsNoTracking().SingleAsync();

        await Assert.That(stored.ConfirmedAt.HasValue).IsFalse();
    }

    private static async Task WrapUnderTheOldKeyAsync(TestApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();
        var current = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
        var old = new AesGcmSecretProtector(Options.Create(new ToamaisutaaTwoFactorOptions { EncryptionKey = OldKey, EncryptionKeyVersion = "1" }));

        var enrolment = await db.UserTwoFactors.SingleAsync();
        // Written the way rows were before they were bound to their user: old key, no binding.
        var wrapped = old.Protect(current.Unprotect(
            new ProtectedSecret(enrolment.SecretCiphertext, enrolment.SecretNonce, enrolment.SecretTag, enrolment.EncryptionKeyVersion),
            enrolment.UserId.ToByteArray()));

        enrolment.SecretCiphertext = wrapped.Ciphertext;
        enrolment.SecretNonce = wrapped.Nonce;
        enrolment.SecretTag = wrapped.Tag;
        enrolment.EncryptionKeyVersion = wrapped.KeyVersion;
        await db.SaveChangesAsync();
    }

    /// <summary>Stands in for another request recording the next step between this one recording
    /// its own and rewrapping.</summary>
    private sealed class RecordsALaterStep
    {
        internal bool Armed { get; set; }

        internal long? Recorded { get; private set; }

        internal Func<Task>? AfterRecording;

        internal void Register(IServiceCollection services) =>
            services.Decorate<ITwoFactorStore>(inner => new Store(this, inner));

        private sealed class Store(RecordsALaterStep owner, ITwoFactorStore inner) : ITwoFactorStore
        {
            public Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.FindAsync(userId, cancellationToken);

            public Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default) =>
                inner.UpsertAsync(enrolment, cancellationToken);

            public Task<bool> ReplacePendingAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default) =>
                inner.ReplacePendingAsync(enrolment, cancellationToken);

            public Task<bool> RewrapSecretAsync(Guid userId, string expectedKeyVersion, byte[] secretCiphertext, byte[] secretNonce, byte[] secretTag, string keyVersion, CancellationToken cancellationToken = default) =>
                inner.RewrapSecretAsync(userId, expectedKeyVersion, secretCiphertext, secretNonce, secretTag, keyVersion, cancellationToken);

            public Task<bool> ConfirmPendingAsync(Guid userId, DateTimeOffset expectedUpdatedAt, DateTimeOffset confirmedAt, CancellationToken cancellationToken = default) =>
                inner.ConfirmPendingAsync(userId, expectedUpdatedAt, confirmedAt, cancellationToken);

            public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
                inner.DeleteAsync(userId, cancellationToken);

            public async Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default)
            {
                if (!await inner.RecordUsedStepAsync(userId, step, cancellationToken))
                    return false;

                if (owner.Armed && await inner.RecordUsedStepAsync(userId, step + 1, cancellationToken))
                    owner.Recorded = step + 1;

                if (Interlocked.Exchange(ref owner.AfterRecording, null) is { } then)
                    await then();

                return true;
            }

            public Task<bool> UpdateFailedAttemptsAsync(Guid userId, int expectedFailedAttemptCount, DateTimeOffset? expectedFirstFailedAttemptAt, DateTimeOffset? expectedLockedOutUntil, int failedAttemptCount, DateTimeOffset? firstFailedAttemptAt, DateTimeOffset? lockedOutUntil, CancellationToken cancellationToken = default) =>
                inner.UpdateFailedAttemptsAsync(userId, expectedFailedAttemptCount, expectedFirstFailedAttemptAt, expectedLockedOutUntil, failedAttemptCount, firstFailedAttemptAt, lockedOutUntil, cancellationToken);
        }
    }
}
