using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class EmailVerificationHttpTests
{
    [Test]
    public async Task Requesting_a_change_answers_204_and_mails_the_new_address()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEmpty();

        var sent = app.IssuedEmailVerifications.Single();
        await Assert.That(sent.Email).IsEqualTo("moved@example.com");
        await Assert.That(sent.Token).IsNotEmpty();
    }

    [Test]
    public async Task Requesting_a_change_requires_authentication()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = "correct horse battery staple" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.IssuedEmailVerifications).IsEmpty();
    }

    [Test]
    public async Task Requesting_a_change_with_the_wrong_password_answers_400()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = "not the password" },
            account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).Strings("errors")).IsNotEmpty();
        await Assert.That(app.IssuedEmailVerifications).IsEmpty();
    }

    [Test]
    public async Task Requesting_an_address_another_account_holds_answers_409()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        // Verified, because an unproven hold gives way to whoever proves the address.
        var grace = await Account.RegisterAsync(app, "grace");
        await grace.VerifyEmailAsync();

        var response = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "grace@example.com", currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        await Assert.That((await response.Json()).Strings("errors")).IsNotEmpty();
    }

    [Test]
    public async Task Redeeming_answers_204_and_the_new_address_signs_in()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        var verify = await app.Client.PostJson(
            "/auth/email/verify",
            new { token = app.IssuedEmailVerifications.Single().Token });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var login = await app.Client.PostJson("/auth/login", new { identifier = "moved@example.com", password = account.Password });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await login.Json()).String("access_token")).IsNotNull();
    }

    [Test]
    public async Task Redeeming_an_unknown_token_answers_400()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.PostJson("/auth/email/verify", new { token = "not-a-real-token" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await response.Json()).Strings("errors")).IsNotEmpty();
    }

    [Test]
    public async Task Email_endpoints_are_not_mapped_without_a_notifier_registered()
    {
        await using var app = await TestApp.StartAsync(includeEmailVerificationNotifier: false);
        var account = await Account.RegisterAsync(app);

        var change = await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        // Authenticated, because an unmatched route meets the fallback policy first and answers 401.
        var verify = await app.Client.PostJson("/auth/email/verify", new { token = "anything" }, account.AccessToken);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
    }

    [Test]
    public async Task Requiring_a_verified_address_still_answers_204_and_sends_nothing()
    {
        var sentResets = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:RequireVerifiedEmailForPasswordReset"] = "true",
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(sentResets)));

        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/password/forgot", new { email = $"{account.UserName}@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(sentResets).IsEmpty();
    }

    [Test]
    public async Task A_verified_address_still_gets_its_reset_link_when_the_option_is_on()
    {
        var sentResets = new List<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["LocalLogin:RequireVerifiedEmailForPasswordReset"] = "true",
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(sentResets)));

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson(
            "/auth/email",
            new { newEmail = $"{account.UserName}@example.com", currentPassword = account.Password },
            account.AccessToken);

        await app.Client.PostJson("/auth/email/verify", new { token = app.IssuedEmailVerifications.Single().Token });

        var response = await app.Client.PostJson("/auth/password/forgot", new { email = $"{account.UserName}@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(sentResets.Count).IsEqualTo(1);
    }

    [Test]
    public async Task An_unverified_address_still_gets_its_reset_link_by_default()
    {
        var sentResets = new List<string>();

        await using var app = await TestApp.StartAsync(
            configureServices: services => services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(sentResets)));

        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/password/forgot", new { email = $"{account.UserName}@example.com" });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(sentResets.Count).IsEqualTo(1);
    }
}
