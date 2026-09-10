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

    // The person reading this is the only one who can tell whether the account should be pointing at
    // their mailbox at all, and they cannot tell without seeing which address is being claimed.
    [Test]
    public async Task NamesTheAddressBeingVerified()
    {
        var content = Template("https://app.example.com/verify?token={token}")
            .Build(User(), "moved@example.com", "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("moved@example.com");
        await Assert.That(content.PlainTextBody).DoesNotContain("old@example.com");
    }

    [Test]
    public async Task ThrowsWhenNoLinkTemplateIsConfigured()
    {
        await Assert.That(() => Template(null).Build(User(), "moved@example.com", "raw-token-123")).Throws<InvalidOperationException>();
    }
}
