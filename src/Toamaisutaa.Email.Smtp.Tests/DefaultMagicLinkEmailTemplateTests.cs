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
    public async Task CarriesNothingTheUserChose()
    {
        var user = User();
        user.DisplayName = "Payroll on hold - https://evil.example";
        user.UserName = "payroll-desk";

        var content = Template("https://app.example.com/magic?token={token}").Build(user, "raw-token-123");

        foreach (var body in new[] { content.PlainTextBody, content.HtmlBody! })
        {
            await Assert.That(body).DoesNotContain("evil.example");
            await Assert.That(body).DoesNotContain("payroll-desk");
        }
    }

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

    [Test]
    public async Task ReadsTheExpiryFromTheConfiguredLifetime()
    {
        var content = Template("https://app.example.com/signin?token={token}", TimeSpan.FromMinutes(40)).Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("40 minutes");

        // The full default, because "5 minutes" would also match "15 minutes".
        await Assert.That(content.PlainTextBody).DoesNotContain("15 minutes");
    }

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
