using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class DefaultPasswordResetEmailTemplateTests
{
    private static DefaultPasswordResetEmailTemplate Template(string? linkTemplate) =>
        new(Options.Create(new ToamaisutaaSmtpEmailOptions { PasswordResetLinkTemplate = linkTemplate, From = "noreply@example.com" }));

    private static ToamaisutaaUser User(string? displayName = "Ada Lovelace", string? userName = "ada") => new()
    {
        Id = Guid.NewGuid(),
        UserName = userName,
        Email = "ada@example.com",
        DisplayName = displayName,
        SecurityStamp = "stamp",
    };

    [Test]
    public async Task SubstitutesTheTokenIntoTheLink()
    {
        var content = Template("https://app.example.com/reset?token={token}").Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("https://app.example.com/reset?token=raw-token-123");
        await Assert.That(content.HtmlBody).IsNotNull();
        await Assert.That(content.HtmlBody!).Contains("https://app.example.com/reset?token=raw-token-123");
    }

    [Test]
    public async Task UrlEncodesTheToken()
    {
        var content = Template("https://app.example.com/reset?token={token}").Build(User(), "a token/with+chars");

        await Assert.That(content.PlainTextBody).Contains("token=" + Uri.EscapeDataString("a token/with+chars"));
        await Assert.That(content.PlainTextBody).DoesNotContain("token=a token/with+chars");
    }

    [Test]
    public async Task ThrowsWhenNoLinkTemplateIsConfigured()
    {
        await Assert.That(() => Template(null).Build(User(), "raw-token-123")).Throws<InvalidOperationException>();
    }

    /// <summary>
    /// Anyone could register with a sentence and a URL for a name and somebody else's address, then
    /// ask for a reset: the mail greeted the stranger's inbox with those words, from this domain.
    /// </summary>
    [Test]
    public async Task CarriesNothingTheUserChose()
    {
        var content = Template("https://app.example.com/reset?token={token}")
            .Build(User(displayName: "Payroll on hold - https://evil.example", userName: "payroll-desk"), "raw-token-123");

        foreach (var body in new[] { content.PlainTextBody, content.HtmlBody! })
        {
            await Assert.That(body).DoesNotContain("evil.example");
            await Assert.That(body).DoesNotContain("payroll-desk");
        }
    }
}
