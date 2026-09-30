using System.Net;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class MagicLinkHttpTests
{
    [Test]
    public async Task Requesting_a_link_answers_204_and_mails_a_verified_address()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var response = await app.Client.PostJson("/auth/magic-link", new { email = account.Email });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEmpty();
        await Assert.That(app.IssuedMagicLinks.Single().Token).IsNotEmpty();
    }

    [Test]
    public async Task Requesting_a_link_for_an_unverified_address_answers_204_and_sends_nothing()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/magic-link", new { email = account.Email });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(app.IssuedMagicLinks).IsEmpty();
    }

    [Test]
    public async Task Requesting_a_link_for_an_unknown_address_answers_204_and_sends_nothing()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson("/auth/magic-link", new { email = "nobody@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(app.IssuedMagicLinks).IsEmpty();
    }

    [Test]
    public async Task Redeeming_answers_the_usual_token_body()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();
        var response = await app.Client.PostJson("/auth/magic-link/verify", new { token });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        // Raw JSON, not TokenResponse, so a field missing on the wire cannot hide behind matching types.
        var body = await response.Json();
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(body.String("token_type")).IsEqualTo("Bearer");
        await Assert.That(body.Has("expires_in")).IsTrue();
    }

    [Test]
    public async Task The_access_token_from_a_link_says_email_in_amr()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();
        var response = await app.Client.PostJson("/auth/magic-link/verify", new { token });

        var claims = Account.DecodeClaims((await response.Json()).String("access_token")!);

        await Assert.That(claims.Amr()).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(claims.Amr()).DoesNotContain("pwd");
    }

    // A recomputed amr goes wrong only one access-token lifetime later, where it reads as a policy failure.
    [Test]
    public async Task A_refreshed_magic_link_session_still_says_email()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();
        var signedIn = await (await app.Client.PostJson("/auth/magic-link/verify", new { token })).Json();

        var refreshed = await app.Client.PostJson("/auth/refresh", new { refreshToken = signedIn.String("refresh_token") });
        var claims = Account.DecodeClaims((await refreshed.Json()).String("access_token")!);

        await Assert.That(refreshed.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(claims.Amr()).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(claims.Amr()).DoesNotContain("pwd");
    }

    [Test]
    public async Task Redeeming_the_same_link_twice_answers_401()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();

        await app.Client.PostJson("/auth/magic-link/verify", new { token });
        var second = await app.Client.PostJson("/auth/magic-link/verify", new { token });

        await Assert.That(second.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await second.Json()).String("error")).IsEqualTo("invalid_grant");
    }

    [Test]
    public async Task Redeeming_an_unknown_token_answers_401()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson("/auth/magic-link/verify", new { token = "not-a-real-token" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Redeeming_stops_for_a_second_factor_when_one_is_enrolled()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();
        var response = await app.Client.PostJson("/auth/magic-link/verify", new { token });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var body = await response.Json();
        await Assert.That(body.Bool("two_factor_required")).IsTrue();
        await Assert.That(body.String("challenge")).IsNotNull();
        await Assert.That(body.Has("access_token")).IsFalse();
    }

    [Test]
    public async Task The_challenge_is_finished_at_the_ordinary_verify_endpoint()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        await account.VerifyEmailAsync();

        var token = await account.RequestMagicLinkAsync();
        var challenge = (await (await app.Client.PostJson("/auth/magic-link/verify", new { token })).Json()).String("challenge")!;

        app.Time.AdvanceToNextTotpStep();

        var verify = await app.Client.PostJson(
            "/auth/2fa/verify",
            new { challenge, code = Totp.Code(account.Secret!, app.Time.Now) });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var claims = Account.DecodeClaims((await verify.Json()).String("access_token")!);
        var methods = claims.Amr();

        await Assert.That(methods).Contains(ToamaisutaaDefaults.MagicLinkMethod);
        await Assert.That(methods).Contains("otp");
        await Assert.That(methods).Contains(ToamaisutaaDefaults.MultiFactorMethod);
        await Assert.That(methods).DoesNotContain("pwd");
    }

    [Test]
    public async Task A_password_sign_in_through_a_challenge_still_says_pwd()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var methods = Account.DecodeClaims(account.AccessToken).Amr();

        await Assert.That(methods).Contains("pwd");
        await Assert.That(methods).DoesNotContain(ToamaisutaaDefaults.MagicLinkMethod);
    }

    [Test]
    public async Task Magic_link_endpoints_are_not_mapped_without_a_notifier_registered()
    {
        await using var app = await TestApp.StartAsync(includeMagicLinkNotifier: false);
        var account = await Account.RegisterAsync(app);

        // Authenticated, because an unmatched route meets the fallback policy first and answers 401, which says nothing about mapping.
        var request = await app.Client.PostJson("/auth/magic-link", new { email = account.Email }, account.AccessToken);
        var verify = await app.Client.PostJson("/auth/magic-link/verify", new { token = "anything" }, account.AccessToken);

        await Assert.That(request.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }
}
