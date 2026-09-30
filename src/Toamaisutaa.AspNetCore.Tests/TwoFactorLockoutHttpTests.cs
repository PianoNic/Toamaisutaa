using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The rate limiter is off in the test host on purpose: an attacker chooses how many addresses they
/// have, so the account-wide count has to hold on its own.
/// </summary>
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
    /// A wrong proof does not move the security stamp, so a stolen token survives every guess and
    /// only the lockout stops it.
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

    [Test]
    public async Task Wrong_codes_at_confirm_lock_the_account_so_the_right_code_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        for (var i = 0; i < Threshold; i++)
        {
            app.Time.AdvanceToNextTotpStep();
            var wrong = Totp.WrongCode(secret, app.Time.Now);

            await Assert.That((await app.Client.PostJson("/auth/2fa/confirm", new { code = wrong }, account.AccessToken)).StatusCode)
                .IsEqualTo(HttpStatusCode.BadRequest);
        }

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, account.AccessToken);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", account.AccessToken)).Json().Result.Bool("enabled")).IsFalse();
    }

    /// <summary>
    /// An account an identity provider owns has no password to keep the account-wide count on, so
    /// the per-address limit has to be on these routes too.
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

    [Test]
    public async Task A_challenge_issued_before_a_password_change_cannot_be_finished_after_it()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = await ChallengeAsync(account);

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            account.AccessToken);

        var finished = await VerifyAsync(app, account, challenge, right: true);

        await Assert.That(finished.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Parallel_codes_are_checked_no_more_often_than_the_lockout_allows()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = await ChallengeAsync(account);
        app.Time.AdvanceToNextTotpStep();
        var wrong = Wrong(account, app);

        using var probe = new InstrumentProbe(app, "toamaisutaa.two_factor.verifications");

        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            app.Client.PostJson("/auth/2fa/verify", new { challenge, code = wrong })));

        // Exactly, not at most: a probe bound to a renamed instrument counts nothing, and zero is at most.
        await Assert.That(probe.Total).IsEqualTo(Threshold);
    }

    [Test]
    public async Task Parallel_passwords_are_checked_no_more_often_than_the_lockout_allows()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        using var probe = new InstrumentProbe(app, "toamaisutaa.password.verification.duration");

        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ =>
            app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" })));

        // A refusal of a locked account runs the dummy derivation too, for the clock, and is tagged
        // no_credential. Only the checks against the real hash are counted.
        // Exactly, not at most: a renamed instrument or tag counts nothing, and zero is at most.
        await Assert.That(probe.Results.Count(result => result == "failed")).IsEqualTo(Threshold);
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

    private static string Wrong(Account account, TestApp app) => Totp.WrongCode(account.Secret!, app.Time.Now);
}
