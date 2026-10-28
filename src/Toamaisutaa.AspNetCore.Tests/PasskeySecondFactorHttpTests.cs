using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>A registered passkey is a second factor: a password or a mailbox alone no longer signs in.</summary>
public class PasskeySecondFactorHttpTests
{
    [Test]
    public async Task A_password_alone_no_longer_signs_in_an_account_with_a_passkey()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var body = await (await account.LoginAsync()).Json();

        await Assert.That(body.Bool("two_factor_required")).IsTrue();
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(body.Strings("second_factors")).IsEquivalentTo(new[] { "passkey" });
    }

    [Test]
    public async Task A_magic_link_alone_no_longer_signs_in_an_account_with_a_passkey()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var token = await account.RequestMagicLinkAsync();
        var body = await (await app.Client.PostJson("/auth/magic-link/verify", new { token })).Json();

        await Assert.That(body.Bool("two_factor_required")).IsTrue();
        await Assert.That(body.Has("access_token")).IsFalse();
    }

    [Test]
    public async Task The_account_s_own_passkey_finishes_the_sign_in_and_says_so_in_the_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge")!;
        var finished = await AnswerAsync(app, challenge, authenticator);

        await Assert.That(finished.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var claims = Account.DecodeClaims((await finished.Json()).String("access_token")!);

        await Assert.That(claims.Amr()).Contains("pwd");
        await Assert.That(claims.Amr()).Contains("hwk");
        await Assert.That(claims.Amr()).Contains("mfa");
        await Assert.That(claims.String("toa_2fa_source")).IsEqualTo("passkey");
    }

    [Test]
    public async Task Another_account_s_passkey_cannot_finish_the_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app, "victim");
        var intruder = await Account.RegisterAsync(app, "intruder");
        using var victimKey = new SoftwareAuthenticator();
        using var intruderKey = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, victim.AccessToken, victimKey);
        await Passkeys.RegisterAsync(app, intruder.AccessToken, intruderKey);

        var challenge = (await (await victim.LoginAsync()).Json()).String("challenge")!;

        await Assert.That((await AnswerAsync(app, challenge, intruderKey)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>Somebody holding the victim's password, and an account and passkey of their own,
    /// begins the ceremony with their own challenge and finishes it with the victim's.</summary>
    [Test]
    public async Task A_ceremony_begun_for_one_sign_in_cannot_finish_another()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app, "victim");
        var intruder = await Account.RegisterAsync(app, "intruder");
        using var victimKey = new SoftwareAuthenticator();
        using var intruderKey = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, victim.AccessToken, victimKey);
        await Passkeys.RegisterAsync(app, intruder.AccessToken, intruderKey);

        var victimChallenge = (await (await victim.LoginAsync()).Json()).String("challenge")!;
        var intruderChallenge = (await (await intruder.LoginAsync()).Json()).String("challenge")!;

        var begin = await app.Client.PostJson("/auth/passkeys/second-factor/begin", new { signInChallenge = intruderChallenge });

        var swapped = await app.Client.PostJson(
            "/auth/passkeys/second-factor/complete",
            new { signInChallenge = victimChallenge, assertion = intruderKey.Get(await begin.Json(), TestApp.Origin) });

        await Assert.That(swapped.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_tampered_signature_does_not_finish_the_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var signInChallenge = (await (await account.LoginAsync()).Json()).String("challenge")!;
        var begin = await app.Client.PostJson("/auth/passkeys/second-factor/begin", new { signInChallenge });

        var assertion = Passkeys.Fields(authenticator.Get(await begin.Json(), TestApp.Origin));
        assertion["signature"] = SoftwareAuthenticator.Encode(new byte[70]);

        var finished = await app.Client.PostJson("/auth/passkeys/second-factor/complete", new { signInChallenge, assertion });

        await Assert.That(finished.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_sign_in_challenge_is_finished_once()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge")!;

        await Assert.That((await AnswerAsync(app, challenge, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await AnswerAsync(app, challenge, authenticator)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task An_account_with_both_is_offered_both()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, currentPassword: null);

        var body = await (await account.LoginAsync()).Json();

        await Assert.That(body.Strings("second_factors")).IsEquivalentTo(new[] { "otp", "passkey" });
    }

    /// <summary>Step-up has no passkey ceremony, so an account whose only second factor is a passkey
    /// is told it has nothing to step up with, rather than handed a challenge no code can answer.</summary>
    [Test]
    public async Task Step_up_still_needs_a_code()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        var stepUp = await app.Client.PostEmpty("/auth/2fa/step-up", account.AccessToken);

        await Assert.That(stepUp.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    private static async Task<HttpResponseMessage> AnswerAsync(TestApp app, string signInChallenge, SoftwareAuthenticator authenticator)
    {
        var begin = await app.Client.PostJson("/auth/passkeys/second-factor/begin", new { signInChallenge });

        if (begin.StatusCode != HttpStatusCode.OK)
            return begin;

        return await app.Client.PostJson(
            "/auth/passkeys/second-factor/complete",
            new { signInChallenge, assertion = authenticator.Get(await begin.Json(), TestApp.Origin) });
    }
}
