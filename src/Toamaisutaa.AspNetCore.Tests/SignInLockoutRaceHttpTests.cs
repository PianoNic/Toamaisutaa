using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

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
