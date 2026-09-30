using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

public class TwoFactorEnrolmentHttpTests
{
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
    public async Task Beginning_again_before_confirming_starts_over_with_a_new_secret()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var first = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var again = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);

        await Assert.That(first.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(again.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var firstSecret = (await first.Json()).String("secret")!;
        var secret = (await again.Json()).String("secret")!;
        await Assert.That(secret).IsNotEqualTo(firstSecret);

        app.Time.AdvanceToNextTotpStep();
        var confirm = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, account.AccessToken);

        await Assert.That(confirm.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task An_enrolment_left_unconfirmed_past_its_lifetime_has_to_begin_again()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.Advance(TimeSpan.FromMinutes(16));
        var late = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, account.AccessToken);

        await Assert.That(late.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", account.AccessToken)).Json().Result.Bool("enabled")).IsFalse();

        var again = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var fresh = (await again.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirmed = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(fresh, app.Time.Now) }, account.AccessToken);

        await Assert.That(confirmed.StatusCode).IsEqualTo(HttpStatusCode.OK);
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
