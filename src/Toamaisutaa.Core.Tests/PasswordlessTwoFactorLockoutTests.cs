using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// A sign-in challenge for an account with no password credential - the one a passkey assertion
/// without user verification leaves. Its wrong-code count lives on the enrolment, because there is no
/// credential to keep it on.
/// </summary>
/// <remarks>
/// Here rather than over HTTP: the endpoints offer no way to build a passkey-only account, since
/// registering a passkey takes a password or a local second factor. The gate issues the challenge
/// exactly as the passkey service does.
/// </remarks>
public class PasswordlessTwoFactorLockoutTests
{
    [Test]
    public async Task Wrong_codes_lock_an_account_with_no_password_so_the_right_code_is_refused()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var challenge = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);

        for (var i = 0; i < harness.Options.MaxFailedAttempts; i++)
        {
            harness.Clock.Now += TimeSpan.FromSeconds(30);
            await harness.SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = "000000" });
        }

        harness.Clock.Now += TimeSpan.FromSeconds(30);
        var right = await harness.SignIn.VerifyTwoFactorAsync(
            new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = harness.CurrentCode(secret) });

        await Assert.That(right.Outcome).IsEqualTo(SignInOutcome.LockedOut);
    }

    [Test]
    public async Task A_right_code_clears_the_count_on_an_account_with_no_password()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        for (var round = 0; round < 2; round++)
        {
            var challenge = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);

            for (var i = 0; i < harness.Options.MaxFailedAttempts - 1; i++)
            {
                harness.Clock.Now += TimeSpan.FromSeconds(30);
                await harness.SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = "000000" });
            }

            harness.Clock.Now += TimeSpan.FromSeconds(30);
            var right = await harness.SignIn.VerifyTwoFactorAsync(
                new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = harness.CurrentCode(secret) });

            await Assert.That(right.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        }
    }

    /// <summary>
    /// The clear was one conditional write, and a wrong code that landed between its read and its
    /// write made it match nothing: the person was signed in with the count still standing, one
    /// typo from a lockout.
    /// </summary>
    [Test]
    public async Task A_right_code_clears_a_count_that_moved_while_it_was_being_cleared()
    {
        var inner = new FakeTwoFactorStore();
        var userId = Guid.NewGuid();
        await inner.UpsertAsync(new ToamaisutaaUserTwoFactor { UserId = userId, FailedAttemptCount = 3 });

        await new CountsOneMoreFirst(inner).RegisterSuccessAsync(userId, CancellationToken.None);

        await Assert.That((await inner.FindAsync(userId))!.FailedAttemptCount).IsEqualTo(0);
    }

    /// <summary>A wrong code from another request, landing just before this one's first write.</summary>
    private sealed class CountsOneMoreFirst(FakeTwoFactorStore inner) : ITwoFactorStore
    {
        private bool _interfered;

        public Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.FindAsync(userId, cancellationToken);

        public Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default) =>
            inner.UpsertAsync(enrolment, cancellationToken);

        public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(userId, cancellationToken);

        public Task<bool> RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default) =>
            inner.RecordUsedStepAsync(userId, step, cancellationToken);

        public async Task<bool> UpdateFailedAttemptsAsync(
            Guid userId,
            int expectedFailedAttemptCount,
            DateTimeOffset? expectedFirstFailedAttemptAt,
            DateTimeOffset? expectedLockedOutUntil,
            int failedAttemptCount,
            DateTimeOffset? firstFailedAttemptAt,
            DateTimeOffset? lockedOutUntil,
            CancellationToken cancellationToken = default)
        {
            if (!_interfered)
            {
                _interfered = true;
                (await inner.FindAsync(userId, cancellationToken))!.FailedAttemptCount++;
            }

            return await inner.UpdateFailedAttemptsAsync(
                userId,
                expectedFailedAttemptCount,
                expectedFirstFailedAttemptAt,
                expectedLockedOutUntil,
                failedAttemptCount,
                firstFailedAttemptAt,
                lockedOutUntil,
                cancellationToken);
        }
    }
}
