using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class LockoutPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    private static ToamaisutaaPasswordCredential Credential() => new()
    {
        UserId = Guid.CreateVersion7(Now),
        UserName = "pianonic",
        NormalizedUserName = "PIANONIC",
        PasswordHash = "irrelevant",
    };

    private static ToamaisutaaLocalLoginOptions Options() => new()
    {
        MaxFailedAttempts = 5,
        LockoutWindow = TimeSpan.FromMinutes(15),
        LockoutDuration = TimeSpan.FromMinutes(15),
    };

    [Test]
    public async Task FourFailuresDoNotLock()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 4; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now.AddSeconds(attempt));

        await Assert.That(LockoutPolicy.IsLockedOut(credential, Now.AddSeconds(5))).IsFalse();
        await Assert.That(credential.FailedAttemptCount).IsEqualTo(4);
    }

    [Test]
    public async Task TheFifthFailureLocks()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 5; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now.AddSeconds(attempt));

        await Assert.That(LockoutPolicy.IsLockedOut(credential, Now.AddSeconds(5))).IsTrue();
        await Assert.That(credential.LockedOutUntil).IsEqualTo(Now.AddSeconds(4) + options.LockoutDuration);
    }

    [Test]
    public async Task TheLockExpires()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 5; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, Now + options.LockoutDuration)).IsFalse();
    }

    // Someone who mistypes once a month is not an attack, and their failures should not accumulate
    // across the years into a lockout.
    [Test]
    public async Task FailuresOutsideTheWindowStartCountingAgain()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 4; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now);

        LockoutPolicy.RegisterFailure(credential, options, Now + options.LockoutWindow + TimeSpan.FromSeconds(1));

        await Assert.That(credential.FailedAttemptCount).IsEqualTo(1);
        await Assert.That(LockoutPolicy.IsLockedOut(credential, Now.AddHours(1))).IsFalse();
    }

    [Test]
    public async Task AFailureExactlyAtTheWindowEdgeStillCounts()
    {
        var credential = Credential();
        var options = Options();

        LockoutPolicy.RegisterFailure(credential, options, Now);
        LockoutPolicy.RegisterFailure(credential, options, Now + options.LockoutWindow);

        await Assert.That(credential.FailedAttemptCount).IsEqualTo(2);
    }

    [Test]
    public async Task SuccessClearsEverything()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 5; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now);

        LockoutPolicy.RegisterSuccess(credential);

        await Assert.That(credential.FailedAttemptCount).IsEqualTo(0);
        await Assert.That(credential.FirstFailedAttemptAt).IsNull();
        await Assert.That(credential.LockedOutUntil).IsNull();
    }

    // A single failure after the lock lifts must not immediately re-lock the account.
    [Test]
    public async Task TheCounterRestartsAfterALock()
    {
        var credential = Credential();
        var options = Options();

        for (var attempt = 0; attempt < 5; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now);

        var afterLock = Now + options.LockoutDuration + TimeSpan.FromSeconds(1);
        LockoutPolicy.RegisterFailure(credential, options, afterLock);

        await Assert.That(credential.FailedAttemptCount).IsEqualTo(1);
        await Assert.That(LockoutPolicy.IsLockedOut(credential, afterLock)).IsFalse();
    }

    [Test]
    public async Task NothingHappensWhenLockoutIsOff()
    {
        var credential = Credential();
        var options = Options();
        options.LockoutEnabled = false;

        for (var attempt = 0; attempt < 20; attempt++)
            LockoutPolicy.RegisterFailure(credential, options, Now);

        await Assert.That(LockoutPolicy.IsLockedOut(credential, Now)).IsFalse();
        await Assert.That(credential.FailedAttemptCount).IsEqualTo(0);
    }
}
