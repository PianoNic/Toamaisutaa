using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Whoever enrols the second factor is the only one who can answer it afterwards, so enrolling has
/// to take more than whatever token the caller is holding.
/// </summary>
public class TwoFactorEnrolmentHttpTests
{
    /// <summary>
    /// A thief with a lifted token used to enrol their own authenticator and confirm it with a code
    /// computed from the secret the response handed them - and the owner's next sign-in stopped at a
    /// challenge only the thief could answer.
    /// </summary>
    [Test]
    public async Task Enrolling_takes_more_than_a_bearer_token()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var empty = await app.Client.PostEmpty("/auth/2fa/begin", account.AccessToken);
        var wrong = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = "not the password" }, account.AccessToken);

        await Assert.That(empty.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(wrong.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var status = await (await app.Client.Get("/auth/2fa", account.AccessToken)).Json();
        await Assert.That(status.Bool("enrolmentPending")).IsFalse();
    }

    [Test]
    public async Task The_current_password_begins_an_enrolment()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);

        await Assert.That(begin.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await begin.Json()).String("secret")).IsNotNull();
    }

    [Test]
    public async Task Wrong_passwords_at_enrolment_lock_the_account()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        for (var i = 0; i < 5; i++)
            await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = "not the password" }, account.AccessToken);

        var right = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await account.LoginAsync()).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }
}
