using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The shape of a sign-in on the wire, asserted by field name.
/// </summary>
/// <remarks>
/// The casing here is the one thing about this API nobody can guess - requests are camelCase,
/// token responses are the RFC 6749 names - so it is asserted rather than described.
/// </remarks>
public class SignInResponseTests
{
    [Test]
    public async Task Login_returns_the_RFC_6749_field_names()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var body = await (await account.LoginAsync()).Json();

        await Assert.That(body.Names()).IsEquivalentTo(new[]
        {
            "access_token",
            "refresh_token",
            "expires_in",
            "token_type",
            "recovery_codes_running_low",
            "device_token",
            "device_expires_in",
        });

        await Assert.That(body.String("token_type")).IsEqualTo("Bearer");
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
    }

    /// <summary>
    /// The branch a client gets wrong. It does not exist until somebody enrols, and then it exists
    /// forever - so a client reading access_token off a 200 works until the first person turns on
    /// two-factor.
    /// </summary>
    [Test]
    public async Task Login_returns_a_challenge_and_no_tokens_once_the_user_has_enrolled()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var response = await account.LoginAsync();
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.Names()).IsEquivalentTo(new[] { "two_factor_required", "challenge", "expires_in" });
        await Assert.That(body.Has("access_token")).IsFalse();
        await Assert.That(body.String("challenge")).IsNotNull();
    }

    [Test]
    public async Task Register_answers_201_with_the_same_body_as_login()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "grace", email = "grace@example.com", password = "correct horse battery staple" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That((await response.Json()).Names()).Contains("access_token");
    }

    [Test]
    public async Task Refresh_rotates_and_returns_the_same_shape()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var first = await (await account.LoginAsync()).Json();
        var refreshed = await (await app.Client.PostJson(
            "/auth/refresh",
            new { refreshToken = first.String("refresh_token") })).Json();

        await Assert.That(refreshed.Names()).IsEquivalentTo(first.Names());
        await Assert.That(refreshed.String("refresh_token")).IsNotEqualTo(first.String("refresh_token"));
    }

    /// <summary>
    /// Wrong password, no such account and locked out are one answer, because telling them apart
    /// tells a caller which user names are real.
    /// </summary>
    [Test]
    [Arguments("ada", "wrong password")]
    [Arguments("nobody-at-all", "correct horse battery staple")]
    public async Task A_refused_credential_is_one_body_whichever_way_it_was_wrong(string identifier, string password)
    {
        await using var app = await TestApp.StartAsync();
        await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/login", new { identifier, password });
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(body.String("error")).IsEqualTo("invalid_grant");
        await Assert.That(body.String("error_description")).IsEqualTo("The credentials are not valid.");
    }

    /// <summary>Input the caller can correct is a different envelope, and camelCase, because no
    /// standard names it.</summary>
    [Test]
    public async Task A_correctable_input_answers_the_errors_array()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = "tiny", email = "tiny@example.com", password = "short" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).Names()).IsEquivalentTo(new[] { "errors" });
    }

    [Test]
    public async Task A_taken_user_name_answers_409()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson(
            "/auth/register",
            new { userName = account.UserName, email = "other@example.com", password = account.Password });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }
}
