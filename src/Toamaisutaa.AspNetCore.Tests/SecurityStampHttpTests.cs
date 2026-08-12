using System.Net;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A token whose security stamp has moved, and the account-probe it must not become.
/// </summary>
/// <remarks>
/// <para>
/// Confirming an enrolment moves the stamp, so the access token that made the call is dead the
/// moment it returns. Nothing mapped the exception, so the next request answered 500 - on the happy
/// path of enrolment, for every client that ever enrolled.
/// </para>
/// <para>
/// The pair of tests at the bottom is the one that matters most. A stale stamp and no token at all
/// must not become the same response: if they did, an unauthenticated caller holding any token
/// could tell an account that exists from one that does not by which body came back.
/// </para>
/// </remarks>
public class SecurityStampHttpTests
{
    private const string StaleDescription =
        "This token was issued before a credential on the account changed. Refresh, or sign in again.";

    /// <summary>Every endpoint that resolves the caller, not only the one enrolment walks through.
    /// There is a single throw site, so the exposure is every caller of it.</summary>
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

        // Changing the password moves the stamp, which is what makes `stale` stale.
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

    /// <summary>The reproduction from the issue, in the order a client meets it.</summary>
    [Test]
    public async Task Confirming_an_enrolment_leaves_the_calling_token_stale_and_the_next_call_answers_401()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostEmpty("/auth/2fa/begin", account.AccessToken);
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

    /// <summary>
    /// The leak this suite exists to prevent. These two answers must stay different shapes.
    /// </summary>
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

        // Same status, deliberately different bodies. Collapsing them would turn "does this account
        // exist" into something an unauthenticated caller can ask.
        await Assert.That(withStaleToken.StatusCode).IsEqualTo(withNoToken.StatusCode);
        await Assert.That(await withStaleToken.Content.ReadAsStringAsync())
            .IsNotEqualTo(await withNoToken.Content.ReadAsStringAsync());
    }

    /// <summary>Endpoints the application owns get this from the documented exception handler
    /// rather than from the package's endpoint filter, so it is worth proving separately.</summary>
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

    /// <summary>
    /// The boundary, asserted so the documentation's claim is checkable rather than a promise.
    /// </summary>
    /// <remarks>
    /// The package's endpoint filter covers the package's endpoints and nothing else. An
    /// application endpoint calling <c>GetOrProvisionAsync</c> without the documented handler still
    /// lets the exception escape - which is exactly why the docs tell you to add it. If this ever
    /// starts failing because the package grew to cover consumer endpoints, delete this test and
    /// the paragraph in Getting started with it.
    /// </remarks>
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

    /// <summary>
    /// The challenge is opaque random bytes rather than a JWT, precisely so that it cannot be
    /// presented as one. A signed challenge would be a valid bearer token held out of the API only
    /// by a validation rule, and rules are configuration a consumer can loosen.
    /// </summary>
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

    /// <summary>A device token is not a bearer token either, and is checked for the same reason.</summary>
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
