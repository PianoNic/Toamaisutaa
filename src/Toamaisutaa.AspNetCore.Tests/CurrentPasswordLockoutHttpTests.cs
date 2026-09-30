using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

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

    /// <summary>The count is shared with the password, so a second factor clearing it would let a
    /// session holder guess, prove a code, and guess again.</summary>
    [Test]
    [Arguments("step-up")]
    [Arguments("/auth/2fa/recovery-codes")]
    public async Task A_right_second_factor_does_not_clear_wrong_passwords(string proveWith)
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        for (var i = 0; i < Threshold - 1; i++)
            await app.Client.PostJson("/auth/password", Body(account, "not the password"), account.AccessToken);

        app.Time.AdvanceToNextTotpStep();

        var proved = proveWith == "step-up"
            ? await account.StepUpAsync()
            : await app.Client.PostJson(proveWith, new { proof = Totp.Code(account.Secret!, app.Time.Now) }, account.AccessToken);

        await Assert.That(proved.IsSuccessStatusCode).IsTrue();

        // At the front door, which reads the same count: new recovery codes move the security stamp,
        // so the access token is no good for the rest of this.
        await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });

        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    private static object Body(Account account, string currentPassword) =>
        new { currentPassword, newPassword = "a whole new passphrase", newEmail = account.Email };
}
