using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class CredentialWritesTests
{
    /// <summary>
    /// Every attempt costs about two writes to one row, so twenty parallel second factors make a
    /// request lose more than ten writes in a row; against the real store a limit of ten failed.
    /// </summary>
    [Test]
    public async Task A_write_that_loses_to_a_burst_of_parallel_attempts_still_lands()
    {
        var inner = new FakePasswordStore();
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await inner.CreateAsync(credential);

        // Twenty requests, two writes each, and this one losing to every other.
        var store = new LosesFirst(inner, times: 39);

        var written = await store.UpdateAsync(credential, current => current.FailedAttemptCount++, CancellationToken.None);

        await Assert.That(written.FailedAttemptCount).IsGreaterThan(0);
    }

    [Test]
    public async Task A_write_that_never_lands_gives_up()
    {
        var inner = new FakePasswordStore();
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await inner.CreateAsync(credential);

        var store = new LosesFirst(inner, times: int.MaxValue);

        await Assert.That(async () => await store.UpdateAsync(credential, current => current.FailedAttemptCount++, CancellationToken.None))
            .Throws<CredentialConcurrencyException>();
    }

    /// <summary>
    /// A right attempt reserved first, then wrong ones reached the lock counting it. Its refund found
    /// someone else's lock and gave nothing back, so the account stayed locked on four wrong guesses.
    /// </summary>
    [Test]
    public async Task A_right_attempt_under_a_lock_another_attempt_set_still_comes_off()
    {
        var store = new FakePasswordStore();
        var options = new ToamaisutaaLocalLoginOptions();
        var now = DateTimeOffset.UtcNow;
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await store.CreateAsync(credential);

        var right = await store.ReserveAttemptAsync(credential, options, now, CancellationToken.None);

        for (var i = 1; i < options.MaxFailedAttempts; i++)
            await store.ReserveAttemptAsync(credential, options, now, CancellationToken.None);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, now)).IsTrue();

        await store.RefundAsync(right, now, CancellationToken.None);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, now)).IsFalse();
        await Assert.That(credential.FailedAttemptCount).IsEqualTo(options.MaxFailedAttempts - 1);
    }

    /// <summary>The right attempt is the one whose reservation locked the account; given back, the
    /// lock goes with it and the count is what it was before.</summary>
    [Test]
    public async Task A_right_attempt_that_set_the_lock_itself_undoes_it()
    {
        var store = new FakePasswordStore();
        var options = new ToamaisutaaLocalLoginOptions();
        var now = DateTimeOffset.UtcNow;
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await store.CreateAsync(credential);

        for (var i = 1; i < options.MaxFailedAttempts; i++)
            await store.ReserveAttemptAsync(credential, options, now, CancellationToken.None);

        var right = await store.ReserveAttemptAsync(credential, options, now, CancellationToken.None);
        await Assert.That(right.LockedByThisAttempt).IsTrue();

        await store.RefundAsync(right, now, CancellationToken.None);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, now)).IsFalse();
        await Assert.That(credential.FailedAttemptCount).IsEqualTo(options.MaxFailedAttempts - 1);
    }

    /// <summary>
    /// The right attempt reserved at the end of one window and a burst locked the account in the next.
    /// That lock never counted the right attempt, and refunding it unlocked the account, so a burst
    /// timed past a right password never served its lockout.
    /// </summary>
    [Test]
    public async Task A_right_attempt_does_not_undo_a_lock_reached_in_a_later_window()
    {
        var store = new FakePasswordStore();
        var options = new ToamaisutaaLocalLoginOptions();
        var start = DateTimeOffset.UtcNow;
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await store.CreateAsync(credential);

        await store.ReserveAttemptAsync(credential, options, start, CancellationToken.None);

        var rightAt = start + options.LockoutWindow - TimeSpan.FromSeconds(1);
        var right = await store.ReserveAttemptAsync(credential, options, rightAt, CancellationToken.None);

        var burstAt = start + options.LockoutWindow + TimeSpan.FromSeconds(1);
        for (var i = 0; i < options.MaxFailedAttempts; i++)
            await store.ReserveAttemptAsync(credential, options, burstAt, CancellationToken.None);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, burstAt)).IsTrue();

        await store.RefundAsync(right, rightAt, CancellationToken.None);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, burstAt)).IsTrue();
    }

    /// <summary>A refund outside the window it was counted in takes nothing off the window that
    /// replaced it.</summary>
    [Test]
    public async Task A_right_attempt_takes_nothing_off_a_later_window()
    {
        var store = new FakePasswordStore();
        var options = new ToamaisutaaLocalLoginOptions();
        var start = DateTimeOffset.UtcNow;
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await store.CreateAsync(credential);

        var right = await store.ReserveAttemptAsync(credential, options, start, CancellationToken.None);

        var later = start + options.LockoutWindow + TimeSpan.FromSeconds(1);
        await store.ReserveAttemptAsync(credential, options, later, CancellationToken.None);
        await store.ReserveAttemptAsync(credential, options, later, CancellationToken.None);

        await store.RefundAsync(right, start, CancellationToken.None);

        await Assert.That(credential.FailedAttemptCount).IsEqualTo(2);
    }

    private sealed class LosesFirst(FakePasswordStore inner, int times) : IPasswordCredentialStore
    {
        private int _lost;

        public Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.FindByUserIdAsync(userId, cancellationToken);

        public Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default) =>
            inner.FindByIdentifierAsync(normalizedIdentifier, cancellationToken);

        public Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
            inner.FindByNormalizedEmailAsync(normalizedEmail, cancellationToken);

        public Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(credential, cancellationToken);

        public Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
            _lost++ < times ? throw new CredentialConcurrencyException() : inner.UpdateAsync(credential, cancellationToken);
    }
}
