using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class DefaultAdminPasswordIssuedEmailTemplateTests
{
    private static DefaultAdminPasswordIssuedEmailTemplate Template(string? signInUrl = null) =>
        new(Options.Create(new ToamaisutaaSmtpEmailOptions { SignInUrl = signInUrl, From = "noreply@example.com" }));

    private static ToamaisutaaUser User(string? userName = "ada") => new()
    {
        Id = Guid.NewGuid(),
        UserName = userName,
        Email = "ada@example.com",
        DisplayName = "Ada Lovelace",
        SecurityStamp = "stamp",
    };

    [Test]
    public async Task CarriesTheUserNameAndThePassword()
    {
        var content = Template().Build(User(), "issued-password-123");

        await Assert.That(content.PlainTextBody).Contains("User name: ada");
        await Assert.That(content.PlainTextBody).Contains("Password: issued-password-123");
        await Assert.That(content.HtmlBody).IsNotNull();
        await Assert.That(content.HtmlBody!).Contains("Password: issued-password-123");
    }

    // A generated password is a random string, so an unencoded one can be swallowed by the email
    // client as markup and shown as a password that was never issued.
    [Test]
    public async Task HtmlEncodesThePassword()
    {
        var content = Template().Build(User(), "a<b>&c");

        await Assert.That(content.HtmlBody!).Contains("a&lt;b&gt;&amp;c");
        await Assert.That(content.HtmlBody!).DoesNotContain("a<b>&c");
        await Assert.That(content.PlainTextBody).Contains("a<b>&c");
    }

    [Test]
    public async Task IncludesTheSignInUrlWhenOneIsConfigured()
    {
        var content = Template("https://app.example.com/login").Build(User(), "issued-password-123");

        await Assert.That(content.PlainTextBody).Contains("Sign in at https://app.example.com/login");
        await Assert.That(content.HtmlBody!).Contains("https://app.example.com/login");
    }

    [Test]
    public async Task LeavesTheSignInLineOutWhenNoUrlIsConfigured()
    {
        var content = Template().Build(User(), "issued-password-123");

        await Assert.That(content.PlainTextBody).DoesNotContain("Sign in at");
    }

    [Test]
    public async Task LeavesTheUserNameLineOutForAnAccountThatHasNoUserNameYet()
    {
        var content = Template().Build(User(userName: null), "issued-password-123");

        await Assert.That(content.PlainTextBody).DoesNotContain("User name:");
        await Assert.That(content.PlainTextBody).Contains("Password: issued-password-123");
    }
}
