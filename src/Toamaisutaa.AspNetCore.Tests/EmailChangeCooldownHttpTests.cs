using System.Net;

namespace Toamaisutaa.AspNetCore.Tests;

public class EmailChangeCooldownHttpTests
{
    [Test]
    public async Task A_second_email_change_inside_the_cooldown_is_refused_and_sends_nothing()
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
            settings["LocalLogin:MailRequestCooldown"] = "00:01:00");

        var account = await Account.RegisterAsync(app);

        var first = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "victim1@example.com", currentPassword = account.Password },
            account.AccessToken);

        var second = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "victim2@example.com", currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(first.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(second.StatusCode).IsEqualTo(HttpStatusCode.TooManyRequests);
        await Assert.That(app.IssuedEmailVerifications).HasCount().EqualTo(1);

        app.Time.Advance(TimeSpan.FromMinutes(1));

        var later = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "victim2@example.com", currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(later.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    [Test]
    public async Task A_refused_email_change_does_not_start_the_cooldown()
    {
        await using var app = await TestApp.StartAsync(configure: settings =>
            settings["LocalLogin:MailRequestCooldown"] = "00:01:00");

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = "not the password" },
            account.AccessToken);

        var retry = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(retry.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }
}
