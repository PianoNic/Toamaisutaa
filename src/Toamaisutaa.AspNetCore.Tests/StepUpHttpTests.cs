using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

public class StepUpHttpTests
{
    [Test]
    public async Task A_session_carries_the_same_toa_sid_across_three_refreshes()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var first = await (await account.LoginAsync()).Json();
        var sid = Account.DecodeClaims(first.String("access_token")!).String("toa_sid");

        await Assert.That(sid).IsNotNull();

        var refreshToken = first.String("refresh_token")!;

        for (var i = 0; i < 3; i++)
        {
            var refreshed = await (await app.Client.PostJson("/auth/refresh", new { refreshToken })).Json();
            refreshToken = refreshed.String("refresh_token")!;

            // If this drifts, every step-up after the first refresh silently elevates nothing.
            await Assert.That(Account.DecodeClaims(refreshed.String("access_token")!).String("toa_sid")).IsEqualTo(sid);
        }
    }

    [Test]
    public async Task Two_sessions_carry_different_toa_sid()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var a = await (await account.LoginAsync()).Json();
        var b = await (await account.LoginAsync()).Json();

        await Assert.That(Account.DecodeClaims(a.String("access_token")!).String("toa_sid"))
            .IsNotEqualTo(Account.DecodeClaims(b.String("access_token")!).String("toa_sid"));
    }

    [Test]
    public async Task Stepping_up_survives_a_refresh()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var signedIn = await account.SignInWithSecondFactorAsync();
        var before = long.Parse(Account.DecodeClaims(signedIn.String("access_token")!).String("toa_2fa_at")!);

        app.Time.Advance(TimeSpan.FromMinutes(4));

        var steppedUp = await account.StepUpAsync();
        await Assert.That(steppedUp.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var elevated = long.Parse(
            Account.DecodeClaims((await steppedUp.Json()).String("access_token")!).String("toa_2fa_at")!);

        await Assert.That(elevated).IsGreaterThan(before);

        // Without the in-place update of the refresh row, freshness silently reverts to the original sign-in here.
        var refreshed = await (await app.Client.PostJson(
            "/auth/refresh",
            new { refreshToken = signedIn.String("refresh_token") })).Json();

        var afterRefresh = long.Parse(
            Account.DecodeClaims(refreshed.String("access_token")!).String("toa_2fa_at")!);

        await Assert.That(afterRefresh).IsEqualTo(elevated);
    }

    [Test]
    public async Task Stepping_up_a_device_trusted_session_replaces_device_with_the_live_factor()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        var trusted = await (await account.LoginAsync(deviceToken: deviceToken)).Json();
        var trustedClaims = Account.DecodeClaims(trusted.String("access_token")!);

        await Assert.That(trustedClaims.String("toa_2fa_source")).IsEqualTo("device");

        var steppedUp = await account.StepUpAsync(accessToken: trusted.String("access_token"));
        var elevated = Account.DecodeClaims((await steppedUp.Json()).String("access_token")!);

        await Assert.That(elevated.String("toa_2fa_source")).IsEqualTo("otp");

        var refreshed = await (await app.Client.PostJson(
            "/auth/refresh",
            new { refreshToken = trusted.String("refresh_token") })).Json();

        // Carried, not recomputed back to device.
        await Assert.That(Account.DecodeClaims(refreshed.String("access_token")!).String("toa_2fa_source")).IsEqualTo("otp");
    }

    [Test]
    public async Task Amr_gains_otp_on_a_step_up_and_loses_nothing()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;
        var trusted = await (await account.LoginAsync(deviceToken: deviceToken)).Json();

        var before = Amr(Account.DecodeClaims(trusted.String("access_token")!));
        await Assert.That(before).IsEquivalentTo(new[] { "pwd", "mfa" });

        var steppedUp = await account.StepUpAsync(accessToken: trusted.String("access_token"));
        var after = Amr(Account.DecodeClaims((await steppedUp.Json()).String("access_token")!));

        await Assert.That(after).IsEquivalentTo(new[] { "pwd", "mfa", "otp" });

        foreach (var method in before)
            await Assert.That(after).Contains(method);
    }

    [Test]
    public async Task A_step_up_challenge_is_refused_at_the_sign_in_endpoint()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var begin = await app.Client.PostEmpty("/auth/2fa/step-up", account.AccessToken);
        var challenge = (await begin.Json()).String("challenge")!;

        app.Time.AdvanceToNextTotpStep();

        var response = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_sign_in_challenge_is_refused_at_the_step_up_endpoint()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = (await account.LoginAsync()).Json().Result.String("challenge")!;

        app.Time.AdvanceToNextTotpStep();

        var response = await app.Client.PostJson(
            "/auth/2fa/step-up/verify",
            new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) },
            account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Both challenges are StepUp for the same user, so only the session binding stops this.
    /// </summary>
    [Test]
    public async Task A_step_up_challenge_from_another_session_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var sessionA = await account.SignInWithSecondFactorAsync();
        var sessionB = await account.SignInWithSecondFactorAsync();

        var begin = await app.Client.PostEmpty("/auth/2fa/step-up", sessionA.String("access_token")!);
        var challengeForA = (await begin.Json()).String("challenge")!;

        app.Time.AdvanceToNextTotpStep();

        var response = await app.Client.PostJson(
            "/auth/2fa/step-up/verify",
            new { challenge = challengeForA, code = Totp.Code(account.Secret!, app.Time.Now) },
            sessionB.String("access_token")!);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Stepping_up_one_session_leaves_another_alone()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var sessionA = await account.SignInWithSecondFactorAsync();
        var sessionB = await account.SignInWithSecondFactorAsync();

        var beforeB = long.Parse(Account.DecodeClaims(sessionB.String("access_token")!).String("toa_2fa_at")!);

        app.Time.Advance(TimeSpan.FromMinutes(4));
        await account.StepUpAsync(accessToken: sessionA.String("access_token"));

        var refreshedB = await (await app.Client.PostJson(
            "/auth/refresh",
            new { refreshToken = sessionB.String("refresh_token") })).Json();

        await Assert.That(long.Parse(Account.DecodeClaims(refreshedB.String("access_token")!).String("toa_2fa_at")!))
            .IsEqualTo(beforeB);
    }

    [Test]
    public async Task A_signed_out_session_cannot_step_up()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var session = await account.SignInWithSecondFactorAsync();

        await app.Client.PostJson("/auth/logout", new { refreshToken = session.String("refresh_token") });

        var response = await app.Client.PostEmpty("/auth/2fa/step-up", session.String("access_token")!);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>400, not 401, because 401 would send the caller to refresh a token that is not the problem.</summary>
    [Test]
    public async Task A_token_with_no_session_claim_answers_400()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var sessionless = app.MintTokenWithoutSession(account.Claims().String("sub")!);

        var response = await app.Client.PostEmpty("/auth/2fa/step-up", sessionless);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).Names()).IsEquivalentTo(new[] { "errors" });
    }

    [Test]
    public async Task A_user_with_no_enrolment_answers_400()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostEmpty("/auth/2fa/step-up", account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).Names()).IsEquivalentTo(new[] { "errors" });
    }

    [Test]
    public async Task A_wrong_code_at_step_up_counts_toward_lockout_and_a_locked_account_is_refused()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var wrong = await account.StepUpAsync(code: "000000");
            await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        }

        var begin = await app.Client.PostEmpty("/auth/2fa/step-up", account.AccessToken);

        await Assert.That(begin.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_recovery_code_steps_up_and_takes_every_trusted_device_with_it()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var recoveryCode = (await account.EnrolForRecoveryCodesAsync())[0];

        var challenge = (await app.Client.PostJson(
            "/auth/login",
            new { identifier = account.UserName, password = account.Password })).Json().Result.String("challenge")!;

        app.Time.AdvanceToNextTotpStep();
        var session = await (await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge, code = Totp.Code(account.Secret!, app.Time.Now), rememberDevice = true })).Json();

        var token = session.String("access_token")!;
        await Assert.That((await app.Client.Get("/auth/devices", token)).Json().Result.GetArrayLength()).IsEqualTo(1);

        var stepUpBegin = await app.Client.PostEmpty("/auth/2fa/step-up", token);
        var stepUpChallenge = (await stepUpBegin.Json()).String("challenge")!;

        var response = await app.Client.PostJson(
            "/auth/2fa/step-up/verify",
            new { challenge = stepUpChallenge, code = recoveryCode },
            token);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var body = await response.Json();
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(Account.DecodeClaims(body.String("access_token")!).String("toa_2fa_source")).IsEqualTo("recovery");

        await Assert.That((await app.Client.Get("/auth/devices", body.String("access_token")!)).Json().Result.GetArrayLength())
            .IsEqualTo(0);
    }

    [Test]
    public async Task Step_up_leaves_the_security_stamp_alone_and_the_session_alive()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var session = await account.SignInWithSecondFactorAsync();
        var before = Account.DecodeClaims(session.String("access_token")!).String("toa_stamp");

        var steppedUp = await account.StepUpAsync(accessToken: session.String("access_token"));
        var after = Account.DecodeClaims((await steppedUp.Json()).String("access_token")!).String("toa_stamp");

        // Bumping it would revoke the session being elevated, so proving you are yourself would sign you out.
        await Assert.That(after).IsEqualTo(before);

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = session.String("refresh_token") });
        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task The_step_up_response_carries_no_refresh_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var body = await (await account.StepUpAsync()).Json();

        await Assert.That(body.Names()).IsEquivalentTo(new[]
        {
            "access_token", "expires_in", "token_type", "recovery_codes_running_low",
        });
    }

    private static IReadOnlyList<string> Amr(System.Text.Json.JsonElement claims)
    {
        var amr = claims.GetProperty("amr");

        return amr.ValueKind == System.Text.Json.JsonValueKind.Array
            ? [.. amr.EnumerateArray().Select(value => value.GetString()!)]
            : [amr.GetString()!];
    }
}
