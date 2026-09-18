using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The current password a signed-in caller answers is a password check like any other, and a
/// stolen access token is all it takes to ask it.
/// </summary>
public class CurrentPasswordLockoutHttpTests
{
    /// <summary>The default <c>MaxFailedAttempts</c>.</summary>
    private const int Threshold = 5;

    [Test]
    [Arguments("/auth/password")]
    [Arguments("/auth/email")]
    public async Task Wrong_current_passwords_lock_the_account(string path)
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < Threshold; i++)
        {
            var wrong = await app.Client.PostJson(path, Body(account, "not the password"), account.AccessToken);
            await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        }

        var right = await app.Client.PostJson(path, Body(account, account.Password), account.AccessToken);
        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        // The same count the sign-in reads, so the guesses cost the guesser the front door too.
        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    [Arguments("/auth/password")]
    [Arguments("/auth/email")]
    public async Task The_current_password_endpoints_are_rate_limited(string path)
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
        {
            settings["LocalLogin:RateLimit:Enabled"] = "true";
            settings["LocalLogin:RateLimit:PermitLimit"] = "3";
            settings["LocalLogin:RateLimit:Window"] = "01:00:00";

            // The lockout would otherwise answer first and hide whether the limiter is there at all.
            settings["LocalLogin:LockoutEnabled"] = "false";
        });

        var account = await Account.RegisterAsync(app);
        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < 4; i++)
            statuses.Add((await app.Client.PostJson(path, Body(account, "not the password"), account.AccessToken)).StatusCode);

        await Assert.That(statuses).Contains(HttpStatusCode.TooManyRequests);
    }

    private static object Body(Account account, string currentPassword) =>
        new { currentPassword, newPassword = "a whole new passphrase", newEmail = account.Email };
}
