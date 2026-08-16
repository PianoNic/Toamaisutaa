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

    [Test]
    public async Task FallsBackToTheUserNameWhenThereIsNoDisplayName()
    {
        var content = Template("https://app.example.com/reset?token={token}").Build(User(displayName: null, userName: "ada"), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("Hi ada,");
    }
}
