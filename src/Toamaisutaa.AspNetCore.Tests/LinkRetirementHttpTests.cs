using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class LinkRetirementHttpTests
{
    [Test]
    public async Task Changing_the_password_retires_an_outstanding_magic_link()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var link = await account.RequestMagicLinkAsync();

        await app.Client.PostJson(
            "/auth/password",
            new { currentPassword = account.Password, newPassword = "an entirely different password" },
            account.AccessToken);

        var redeemed = await app.Client.PostJson("/auth/magic-link/verify", new { token = link });

        await Assert.That(redeemed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Resetting_the_password_retires_an_outstanding_magic_link()
    {
        var resets = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets)));

        var account = await Account.RegisterAsync(app);
        await account.VerifyEmailAsync();

        var link = await account.RequestMagicLinkAsync();

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        await app.Client.PostJson("/auth/password/reset", new { token = resets.Single(), newPassword = "an entirely different password" });

        var redeemed = await app.Client.PostJson("/auth/magic-link/verify", new { token = link });

        await Assert.That(redeemed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Moving_to_a_new_address_retires_an_outstanding_reset_link()
    {
        var resets = new List<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordResetNotifier>(new CapturingResetNotifier(resets)));

        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/password/forgot", new { email = account.Email });
        var link = resets.Single();

        await app.Client.PostJson(
            "/auth/email",
            new { newEmail = "moved@example.com", currentPassword = account.Password },
            account.AccessToken);

        await app.Client.PostJson("/auth/email/verify", new { token = app.IssuedEmailVerifications[^1].Token });

        var redeemed = await app.Client.PostJson("/auth/password/reset", new { token = link, newPassword = "an entirely different password" });

        await Assert.That(redeemed.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }
}
