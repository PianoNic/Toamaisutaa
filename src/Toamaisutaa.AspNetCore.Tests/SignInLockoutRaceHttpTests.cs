using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A right password among a wave of wrong ones, sent together. The wave locks the account while the
/// right one is still being hashed, and the right one used to sign in regardless - clearing the lock
/// the wave had just set on its way out.
/// </summary>
public class SignInLockoutRaceHttpTests
{
    [Test]
    public async Task A_right_password_hashed_while_the_account_locks_is_refused_and_leaves_the_lock()
    {
        var hasher = new HeldHasher();
        await using var app = await TestApp.StartAsync(configureServices: hasher.Register);

        var account = await Account.RegisterAsync(app);
        hasher.Hold = account.Password;

        var right = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        for (var i = 0; i < 5; i++)
            await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });

        hasher.Let();

        await Assert.That((await right).StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        var afterwards = await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await Assert.That(afterwards.StatusCode).IsNotEqualTo(HttpStatusCode.OK);
    }
}
