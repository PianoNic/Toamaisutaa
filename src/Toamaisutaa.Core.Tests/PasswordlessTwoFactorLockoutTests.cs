using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Here rather than over HTTP because the endpoints offer no way to build a passkey-only account;
/// the gate issues the challenge exactly as the passkey service does.
/// </summary>
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

    [Test]
    public async Task A_right_code_that_loses_a_race_leaves_no_failure_on_an_account_with_no_password()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var challenge = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);
        harness.Clock.Now += TimeSpan.FromSeconds(30);
        harness.TwoFactorStore.LoseNextStep = true;

        var lost = await harness.SignIn.VerifyTwoFactorAsync(
            new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = harness.CurrentCode(secret) });

        await Assert.That(lost.Outcome).IsEqualTo(SignInOutcome.ChallengeAlreadyUsed);
        await Assert.That((await harness.TwoFactorStore.FindAsync(user.Id))!.FailedAttemptCount).IsEqualTo(0);
    }

    [Test]
    public async Task A_right_code_that_loses_a_race_undoes_the_lock_it_set()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        var challenge = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);

        for (var i = 0; i < harness.Options.MaxFailedAttempts - 1; i++)
        {
            harness.Clock.Now += TimeSpan.FromSeconds(30);
            await harness.SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = "000000" });
        }

        // The last allowed attempt: its reservation is the one that locks.
        harness.Clock.Now += TimeSpan.FromSeconds(30);
        harness.TwoFactorStore.LoseNextStep = true;
        await harness.SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = harness.CurrentCode(secret) });

        var next = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);
        harness.Clock.Now += TimeSpan.FromSeconds(30);
        var right = await harness.SignIn.VerifyTwoFactorAsync(
            new TwoFactorSignInRequest { ChallengeToken = next.Token, Code = harness.CurrentCode(secret) });

        await Assert.That(right.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task A_right_proof_that_loses_a_race_leaves_no_failure_on_an_account_with_no_password()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        var (secret, _) = await harness.EnrolAsync(user.Id);

        harness.Clock.Now += TimeSpan.FromSeconds(30);
        harness.TwoFactorStore.LoseNextStep = true;

        var lost = await harness.TwoFactor.DisableAsync(user.Id, harness.CurrentCode(secret));

        await Assert.That(lost.Succeeded).IsFalse();
        await Assert.That((await harness.TwoFactorStore.FindAsync(user.Id))!.FailedAttemptCount).IsEqualTo(0);
    }

    [Test]
    public async Task Locking_an_account_with_no_password_at_sign_in_is_reported_once()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        await harness.EnrolAsync(user.Id);
        using var probe = new MeterProbe(harness.Metrics.Meter);

        var challenge = await harness.Gate.IssueChallengeAsync(user.Id, harness.Clock.GetUtcNow(), CancellationToken.None);

        for (var i = 0; i < harness.Options.MaxFailedAttempts + 1; i++)
        {
            harness.Clock.Now += TimeSpan.FromSeconds(30);
            await harness.SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest { ChallengeToken = challenge.Token, Code = "000000" });
        }

        await Assert.That(harness.Events.OfKind<AccountLockedOut>()).HasCount().EqualTo(1);
        await Assert.That(probe.For("toamaisutaa.lockouts")).HasCount().EqualTo(1);
    }

    [Test]
    public async Task Locking_an_account_with_no_password_with_proofs_is_reported_once()
    {
        var harness = PasswordHarness.Create(withTwoFactor: true);
        var user = harness.ProvisionExternalUser();
        await harness.EnrolAsync(user.Id);
        using var probe = new MeterProbe(harness.Metrics.Meter);

        for (var i = 0; i < harness.Options.MaxFailedAttempts + 1; i++)
        {
            harness.Clock.Now += TimeSpan.FromSeconds(30);
            await harness.TwoFactor.DisableAsync(user.Id, "000000");
        }

        await Assert.That(harness.Events.OfKind<AccountLockedOut>()).HasCount().EqualTo(1);
        await Assert.That(probe.For("toamaisutaa.lockouts")).HasCount().EqualTo(1);
    }

    /// <summary>
    /// A wrong code landing between the clear's read and its conditional write must not leave the
    /// count standing.
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
