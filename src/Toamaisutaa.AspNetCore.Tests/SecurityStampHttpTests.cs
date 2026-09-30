using System.Net;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class SecurityStampHttpTests
{
    private const string StaleDescription =
        "This token was issued before a credential on the account changed. Refresh, or sign in again.";

    [Test]
    [Arguments("GET", "/auth/2fa")]
    [Arguments("POST", "/auth/2fa/begin")]
    [Arguments("GET", "/auth/devices")]
    [Arguments("DELETE", "/auth/devices")]
    public async Task A_stale_stamp_answers_401_rather_than_throwing(string method, string path)
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var stale = account.AccessToken;

        var changed = await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);
        await Assert.That(changed.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var request = new HttpRequestMessage(new HttpMethod(method), path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", stale);

        var response = await app.Client.SendAsync(request);
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(body.String("error")).IsEqualTo("invalid_token");
        await Assert.That(body.String("error_description")).IsEqualTo(StaleDescription);
    }

    [Test]
    public async Task Confirming_an_enrolment_leaves_the_calling_token_stale_and_the_next_call_answers_401()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(secret, app.Time.Now) },
            account.AccessToken);

        await Assert.That(confirm.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var next = await app.Client.Get("/auth/2fa", account.AccessToken);

        await Assert.That(next.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await next.Json()).String("error")).IsEqualTo("invalid_token");
    }

    [Test]
    public async Task A_stale_stamp_names_the_reason_in_WWW_Authenticate()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);

        var response = await app.Client.Get("/auth/2fa", stale);
        var header = string.Join(' ', response.Headers.WwwAuthenticate.Select(value => value.ToString()));

        await Assert.That(header).Contains("error=\"invalid_token\"");
    }

    [Test]
    public async Task No_token_at_all_answers_a_bare_401_with_no_body()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.Get("/auth/2fa");
        var body = await response.Content.ReadAsStringAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(body).IsEmpty();
    }

    [Test]
    public async Task A_stale_stamp_and_no_token_are_not_the_same_response()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);

        var withStaleToken = await app.Client.Get("/auth/2fa", stale);
        var withNoToken = await app.Client.Get("/auth/2fa");

        // Collapsing these bodies would let an unauthenticated caller ask whether an account exists.
        await Assert.That(withStaleToken.StatusCode).IsEqualTo(withNoToken.StatusCode);
        await Assert.That(await withStaleToken.Content.ReadAsStringAsync())
            .IsNotEqualTo(await withNoToken.Content.ReadAsStringAsync());
    }

    [Test]
    public async Task An_application_endpoint_answers_401_through_the_documented_handler()
    {
        await using var app = await TestApp.StartAsync(handleStaleStampGlobally: true);
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await Assert.That((await app.Client.Get("/test/me", stale)).StatusCode).IsEqualTo(HttpStatusCode.OK);

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);

        var response = await app.Client.Get("/test/me", stale);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).String("error")).IsEqualTo("invalid_token");
    }

    /// <summary>Pins the boundary the Getting started handler paragraph relies on; if the package
    /// grows to cover consumer endpoints, delete this test and that paragraph together.</summary>
    [Test]
    public async Task Without_the_handler_an_application_endpoint_does_not_get_this_for_free()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        var stale = account.AccessToken;

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            stale);

        await Assert.That(async () => await app.Client.Get("/test/me", stale))
            .Throws<SecurityStampChangedException>();
    }

    [Test]
    public async Task A_challenge_token_is_refused_as_a_bearer_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var challenge = (await account.LoginAsync()).Json().Result.String("challenge")!;

        var response = await app.Client.Get("/test/me", challenge);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_device_token_is_refused_as_a_bearer_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var deviceToken = (await account.SignInWithSecondFactorAsync(rememberDevice: true)).String("device_token")!;

        var response = await app.Client.Get("/test/me", deviceToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }
}
