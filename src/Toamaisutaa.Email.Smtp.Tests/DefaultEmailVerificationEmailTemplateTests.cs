using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class DefaultEmailVerificationEmailTemplateTests
{
    private static DefaultEmailVerificationEmailTemplate Template(string? linkTemplate) =>
        new(Options.Create(new ToamaisutaaSmtpEmailOptions { EmailVerificationLinkTemplate = linkTemplate, From = "noreply@example.com" }));

    private static ToamaisutaaUser User() => new()
    {
        Id = Guid.NewGuid(),
        UserName = "ada",
        Email = "old@example.com",
        DisplayName = "Ada",
        SecurityStamp = "stamp",
    };

    [Test]
    public async Task WarnsWhenTheLinkTakesTheAddressFromAnotherAccount()
    {
        var template = Template("https://app.example.com/verify?token={token}");

        var warned = template.Build(User(), "held@example.com", "raw", new EmailVerificationContext { TakesFromAnotherAccount = true });
        var ordinary = template.Build(User(), "held@example.com", "raw", new EmailVerificationContext());

        await Assert.That(warned.Subject).IsEqualTo("Someone wants to move your email address to their account");
        await Assert.That(warned.PlainTextBody).Contains("moves it away from that account");
        await Assert.That(warned.HtmlBody!).Contains("moves it away from that account");
        await Assert.That(warned.PlainTextBody).Contains("https://app.example.com/verify?token=raw");
        await Assert.That(ordinary.Subject).IsEqualTo("Verify your email address");
    }

    /// <summary>The user name is chosen by whoever asked, and this goes to somebody else's inbox.</summary>
    [Test]
    public async Task TheWarningNamesNoAccount()
    {
        var warned = Template("https://app.example.com/verify?token={token}")
            .Build(User(), "held@example.com", "raw", new EmailVerificationContext { TakesFromAnotherAccount = true });

        await Assert.That(warned.PlainTextBody).DoesNotContain("ada");
        await Assert.That(warned.HtmlBody!).DoesNotContain("ada");
    }

    [Test]
    public async Task SubstitutesTheTokenIntoTheLink()
    {
        var content = Template("https://app.example.com/verify?token={token}")
            .Build(User(), "moved@example.com", "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("https://app.example.com/verify?token=raw-token-123");
        await Assert.That(content.HtmlBody).IsNotNull();
        await Assert.That(content.HtmlBody!).Contains("https://app.example.com/verify?token=raw-token-123");
    }

    [Test]
    public async Task UrlEncodesTheToken()
    {
        var content = Template("https://app.example.com/verify?token={token}")
            .Build(User(), "moved@example.com", "a token/with+chars");

        await Assert.That(content.PlainTextBody).Contains("token=" + Uri.EscapeDataString("a token/with+chars"));
        await Assert.That(content.PlainTextBody).DoesNotContain("token=a token/with+chars");
    }

    [Test]
    public async Task NamesTheAddressBeingVerified()
    {
        var content = Template("https://app.example.com/verify?token={token}")
            .Build(User(), "moved@example.com", "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("moved@example.com");
        await Assert.That(content.PlainTextBody).DoesNotContain("old@example.com");
    }

    /// <summary>Greeting by the registered name would let anyone mail their own words from this domain
    /// to any inbox.</summary>
    [Test]
    public async Task CarriesNothingTheUserChose()
    {
        var user = User();
        user.DisplayName = "Claim your refund at https://evil.example";
        user.UserName = "refund-desk";

        var content = Template("https://app.example.com/verify?token={token}")
            .Build(user, "victim@example.com", "raw-token-123");

        foreach (var body in new[] { content.PlainTextBody, content.HtmlBody! })
        {
            await Assert.That(body).DoesNotContain("evil.example");
            await Assert.That(body).DoesNotContain("refund-desk");
        }
    }

    [Test]
    public async Task ThrowsWhenNoLinkTemplateIsConfigured()
    {
        await Assert.That(() => Template(null).Build(User(), "moved@example.com", "raw-token-123")).Throws<InvalidOperationException>();
    }
}
