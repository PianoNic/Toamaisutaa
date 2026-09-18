using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Wrong second factors count against the account, at sign-in as at step-up.
/// </summary>
/// <remarks>
/// The rate limiter is off in the test host, so nothing here is saved by the per-address limit.
/// That is the point: it partitions on an address, and an attacker holding the password chooses
/// how many addresses they have. The account-wide count is what has to hold on its own.
/// </remarks>
public class TwoFactorLockoutHttpTests
{
    /// <summary>The default <c>MaxFailedAttempts</c>.</summary>
    private const int Threshold = 5;

    [Test]
    public async Task Wrong_codes_at_sign_in_lock_the_account_so_the_right_code_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = await ChallengeAsync(account);

        for (var i = 0; i < Threshold; i++)
            await Assert.That((await VerifyAsync(app, account, challenge, right: false)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);

        var right = await VerifyAsync(app, account, challenge, right: true);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// A right password used to clear the count before any code was asked for, so signing in again
    /// every few guesses bought an unlimited supply of them.
    /// </summary>
    [Test]
    public async Task Signing_in_again_does_not_clear_the_wrong_codes()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var first = await ChallengeAsync(account);

        for (var i = 0; i < Threshold - 1; i++)
            await VerifyAsync(app, account, first, right: false);

        var second = await ChallengeAsync(account);
        await VerifyAsync(app, account, second, right: false);

        var right = await VerifyAsync(app, account, second, right: true);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>The other side of the count: a person who mistypes and then gets it right is not
    /// carrying those mistakes into their next sign-in.</summary>
    [Test]
    public async Task A_completed_sign_in_clears_the_wrong_codes()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        for (var round = 0; round < 2; round++)
        {
            var challenge = await ChallengeAsync(account);

            for (var i = 0; i < Threshold - 1; i++)
                await VerifyAsync(app, account, challenge, right: false);

            var right = await VerifyAsync(app, account, challenge, right: true);

            await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.OK);
        }
    }

    [Test]
    public async Task Wrong_codes_at_step_up_lock_the_account_so_the_right_code_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        app.Time.AdvanceToNextTotpStep();

        for (var i = 0; i < Threshold; i++)
            await Assert.That((await account.StepUpAsync(code: Wrong(account, app))).StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        var begin = await app.Client.PostEmpty("/auth/2fa/step-up", account.AccessToken);

        await Assert.That(begin.StatusCode).IsNotEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// Both endpoints take a code as proof and pay out the second factor itself - ten fresh recovery
    /// codes, or no second factor at all - so a stolen access token must not be able to guess there
    /// either. A wrong proof does not move the security stamp, so the token survives every guess.
    /// </summary>
    [Test]
    [Arguments("/auth/2fa/recovery-codes")]
    [Arguments("/auth/2fa/disable")]
    public async Task Wrong_proofs_lock_the_account_so_the_right_code_is_refused(string path)
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        for (var i = 0; i < Threshold; i++)
        {
            app.Time.AdvanceToNextTotpStep();
            var wrong = await app.Client.PostJson(path, new { proof = Wrong(account, app) }, account.AccessToken);
            await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        }

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson(path, new { proof = Totp.Code(account.Secret!, app.Time.Now) }, account.AccessToken);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", account.AccessToken)).Json().Result.Bool("enabled")).IsTrue();
    }

    /// <summary>
    /// The account-wide count cannot reach an account an identity provider owns, which has no
    /// password to keep it on, so the per-address limit has to be on these routes too.
    /// </summary>
    [Test]
    [Arguments("/auth/2fa/confirm")]
    [Arguments("/auth/2fa/recovery-codes")]
    [Arguments("/auth/2fa/disable")]
    public async Task The_code_taking_management_endpoints_are_rate_limited(string path)
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
        {
            settings["LocalLogin:RateLimit:Enabled"] = "true";
            settings["LocalLogin:RateLimit:PermitLimit"] = "10";
            settings["LocalLogin:RateLimit:Window"] = "01:00:00";
        });

        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < 10; i++)
            statuses.Add((await app.Client.PostJson(path, new { code = "000000", proof = "000000" }, account.AccessToken)).StatusCode);

        await Assert.That(statuses).Contains(HttpStatusCode.TooManyRequests);
    }

    private static async Task<string> ChallengeAsync(Account account)
    {
        var body = await (await account.LoginAsync()).Json();
        return body.String("challenge") ?? throw new InvalidOperationException("Sign-in did not ask for a second factor.");
    }

    /// <summary>A fresh step each time, so a right code is never refused as a replay instead of
    /// for the reason under test.</summary>
    private static Task<HttpResponseMessage> VerifyAsync(TestApp app, Account account, string challenge, bool right)
    {
        app.Time.AdvanceToNextTotpStep();
        var code = right ? Totp.Code(account.Secret!, app.Time.Now) : Wrong(account, app);
        return app.Client.PostJson("/auth/2fa/verify", new { challenge, code });
    }

    /// <summary>The right code with its first digit moved on, which no drift step will also produce
    /// outside a one-in-a-million coincidence.</summary>
    private static string Wrong(Account account, TestApp app)
    {
        var code = Totp.Code(account.Secret!, app.Time.Now);
        return (char)('0' + ((code[0] - '0' + 1) % 10)) + code[1..];
    }
}
