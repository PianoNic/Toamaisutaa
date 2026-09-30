using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class ConcurrentCredentialWriteHttpTests
{
    /// <summary>Parallel requests that write the count back whole all write the same c+1, so the
    /// lockout never arrives.</summary>
    [Test]
    public async Task Parallel_wrong_passwords_still_lock_the_account()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var attempts = Enumerable.Range(0, 10).Select(_ =>
            app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" }));

        await Task.WhenAll(attempts);

        var right = await account.LoginAsync();

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>Two scopes over the real database pin down an interleaving an HTTP race only hits by
    /// luck.</summary>
    [Test]
    public async Task A_write_from_a_stale_read_does_not_undo_a_password_reset()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await using var signIn = app.Services.CreateAsyncScope();
        await using var reset = app.Services.CreateAsyncScope();

        var signInStore = signIn.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
        var resetStore = reset.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();

        var stale = (await signInStore.FindByUserIdAsync(userId))!;
        var current = (await resetStore.FindByUserIdAsync(userId))!;

        current.PasswordHash = "reset-hash";
        await resetStore.UpdateAsync(current);

        stale.FailedAttemptCount++;

        await Assert.That(async () => await signInStore.UpdateAsync(stale)).Throws<CredentialConcurrencyException>();

        await using var check = app.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<IPasswordCredentialStore>().FindByUserIdAsync(userId);

        await Assert.That(stored!.PasswordHash).IsEqualTo("reset-hash");
    }

    /// <summary>
    /// One failure whose window has run out: every reservation restarts the window at a count of one,
    /// so the count never changes, and a write conditional on the count let a whole burst of stale
    /// reservations through unlimited.
    /// </summary>
    [Test]
    public async Task A_window_restart_from_a_stale_read_conflicts_with_one_that_landed()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });
        app.Time.Advance(TimeSpan.FromHours(1));

        await using var first = app.Services.CreateAsyncScope();
        await using var second = app.Services.CreateAsyncScope();

        var firstStore = first.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();
        var secondStore = second.ServiceProvider.GetRequiredService<IPasswordCredentialStore>();

        var winner = (await firstStore.FindByUserIdAsync(userId))!;
        var stale = (await secondStore.FindByUserIdAsync(userId))!;

        await Assert.That(winner.FailedAttemptCount).IsEqualTo(1);

        winner.FirstFailedAttemptAt = app.Time.Now;
        await firstStore.UpdateAsync(winner);

        stale.FirstFailedAttemptAt = app.Time.Now.AddSeconds(1);

        await Assert.That(async () => await secondStore.UpdateAsync(stale)).Throws<CredentialConcurrencyException>();
    }

    /// <summary>A lock resets the count to zero, so a stale write conditional on the count alone would
    /// still match and clear the lock.</summary>
    [Test]
    public async Task A_stale_wrong_code_write_does_not_clear_a_lock_on_the_enrolment()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await using var stale = app.Services.CreateAsyncScope();
        await using var locking = app.Services.CreateAsyncScope();

        var staleStore = stale.ServiceProvider.GetRequiredService<ITwoFactorStore>();
        var before = (await staleStore.FindAsync(userId))!;
        var read = (Count: before.FailedAttemptCount, First: before.FirstFailedAttemptAt, Until: before.LockedOutUntil);

        var lockedUntil = app.Time.Now.AddMinutes(15);
        var locked = await locking.ServiceProvider.GetRequiredService<ITwoFactorStore>()
            .UpdateFailedAttemptsAsync(userId, read.Count, read.First, read.Until, 0, null, lockedUntil);

        await Assert.That(locked).IsTrue();

        var landed = await staleStore.UpdateFailedAttemptsAsync(userId, read.Count, read.First, read.Until, 1, app.Time.Now, null);

        await using var check = app.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<ITwoFactorStore>().FindAsync(userId);

        await Assert.That(landed).IsFalse();
        await Assert.That(stored!.LockedOutUntil.HasValue).IsTrue();
    }

    [Test]
    public async Task A_profile_sync_from_a_stale_read_does_not_undo_a_security_stamp_change()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await using var sync = app.Services.CreateAsyncScope();
        await using var change = app.Services.CreateAsyncScope();

        var syncUsers = sync.ServiceProvider.GetRequiredService<IUserStore>();
        var stale = (await syncUsers.FindByIdAsync(userId))!;

        await change.ServiceProvider.GetRequiredService<IUserStore>().UpdateSecurityStampAsync(userId, "after-the-change");

        await syncUsers.UpdateProfileAsync(stale, new ExternalUserProfile { Subject = "irrelevant", DisplayName = "Ada Lovelace" });

        await using var check = app.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<IUserStore>().FindByIdAsync(userId);

        await Assert.That(stored!.SecurityStamp).IsEqualTo("after-the-change");
        await Assert.That(stored.DisplayName).IsEqualTo("Ada Lovelace");
    }

    /// <summary>The change is held in the hasher, between checking the old password and writing the new
    /// one, so the reset lands inside it and the change's conflicting write must not retry over it.</summary>
    [Test]
    public async Task A_password_change_does_not_write_over_a_reset_that_landed_first()
    {
        var hasher = new HeldHasher();
        var resets = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            hasher.Register(services);
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets));
        });

        var account = await Account.RegisterAsync(app);
        const string changed = "the password the change sets";
        const string reset = "the password the owner reset to";

        hasher.Hold = changed;

        var change = app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = changed },
            account.AccessToken);

        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        var resetResponse = await app.Client.PostJson("/auth/password/reset", new { token = resets.Single(), newPassword = reset });
        await Assert.That(resetResponse.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        hasher.Let();

        await Assert.That((await change).IsSuccessStatusCode).IsFalse();

        var signIn = await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = reset });
        await Assert.That(signIn.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }
}
