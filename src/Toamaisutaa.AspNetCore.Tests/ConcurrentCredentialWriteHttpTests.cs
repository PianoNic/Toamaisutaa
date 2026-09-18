using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Credential writes that race each other, which is the normal condition for an account under a
/// guessing attack rather than an edge case.
/// </summary>
public class ConcurrentCredentialWriteHttpTests
{
    /// <summary>
    /// Every request reads the count, spends a key derivation, and writes the count back. Written
    /// back whole, parallel requests all write the same c+1 and the lockout never arrives.
    /// </summary>
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

    /// <summary>
    /// The interleaving an HTTP race only hits by luck, pinned down with two scopes over the real
    /// database: a sign-in reads the row, a reset writes a new hash, and then the sign-in writes. It
    /// must not land, or the reset the owner just did to lock somebody out is quietly undone.
    /// </summary>
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
}
