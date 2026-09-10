using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class DefaultMagicLinkEmailTemplateTests
{
    private static DefaultMagicLinkEmailTemplate Template(string? linkTemplate, TimeSpan? lifetime = null) =>
        new(
            Options.Create(new ToamaisutaaSmtpEmailOptions { MagicLinkTemplate = linkTemplate, From = "noreply@example.com" }),
            Options.Create(new ToamaisutaaLocalLoginOptions { MagicLinkTokenLifetime = lifetime ?? TimeSpan.FromMinutes(15) }));

    private static ToamaisutaaUser User() => new()
    {
        Id = Guid.NewGuid(),
        UserName = "ada",
        Email = "ada@example.com",
        DisplayName = "Ada",
        SecurityStamp = "stamp",
    };

    [Test]
    public async Task SubstitutesTheTokenIntoTheLink()
    {
        var content = Template("https://app.example.com/signin?token={token}").Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("https://app.example.com/signin?token=raw-token-123");
        await Assert.That(content.HtmlBody).IsNotNull();
        await Assert.That(content.HtmlBody!).Contains("https://app.example.com/signin?token=raw-token-123");
    }

    [Test]
    public async Task UrlEncodesTheToken()
    {
        var content = Template("https://app.example.com/signin?token={token}").Build(User(), "a token/with+chars");

        await Assert.That(content.PlainTextBody).Contains("token=" + Uri.EscapeDataString("a token/with+chars"));
        await Assert.That(content.PlainTextBody).DoesNotContain("token=a token/with+chars");
    }

    // The expiry comes from the lifetime that actually governs the token, not from a second setting
    // that would eventually disagree with it.
    [Test]
    public async Task ReadsTheExpiryFromTheConfiguredLifetime()
    {
        var content = Template("https://app.example.com/signin?token={token}", TimeSpan.FromMinutes(40)).Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("40 minutes");

        // The default, spelled out: "5 minutes" would also match "15 minutes", which is how an
        // assertion agrees with a hardcoded number it was written to catch.
        await Assert.That(content.PlainTextBody).DoesNotContain("15 minutes");
    }

    // Every other link this package sends leads to a form that asks for something else first. This
    // one does not, and the wording has to say so.
    [Test]
    public async Task WarnsThatTheLinkSignsAnyoneIn()
    {
        var content = Template("https://app.example.com/signin?token={token}").Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("do not forward");
    }

    [Test]
    public async Task ThrowsWhenNoLinkTemplateIsConfigured()
    {
        await Assert.That(() => Template(null).Build(User(), "raw-token-123")).Throws<InvalidOperationException>();
    }
}
