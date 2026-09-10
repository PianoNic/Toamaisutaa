using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class DefaultInvitationEmailTemplateTests
{
    private static DefaultInvitationEmailTemplate Template(string? linkTemplate) =>
        new(Options.Create(new ToamaisutaaSmtpEmailOptions { InvitationLinkTemplate = linkTemplate, From = "noreply@example.com" }));

    private static ToamaisutaaUser User(string? displayName = null, string? userName = null) => new()
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
        var content = Template("https://app.example.com/invite?token={token}").Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("https://app.example.com/invite?token=raw-token-123");
        await Assert.That(content.HtmlBody).IsNotNull();
        await Assert.That(content.HtmlBody!).Contains("https://app.example.com/invite?token=raw-token-123");
    }

    [Test]
    public async Task UrlEncodesTheToken()
    {
        var content = Template("https://app.example.com/invite?token={token}").Build(User(), "a token/with+chars");

        await Assert.That(content.PlainTextBody).Contains("token=" + Uri.EscapeDataString("a token/with+chars"));
        await Assert.That(content.PlainTextBody).DoesNotContain("token=a token/with+chars");
    }

    [Test]
    public async Task ThrowsWhenNoLinkTemplateIsConfigured()
    {
        await Assert.That(() => Template(null).Build(User(), "raw-token-123")).Throws<InvalidOperationException>();
    }

    // A reserved row has neither name until the invitation is completed, which is the ordinary case
    // here rather than an edge one.
    [Test]
    public async Task GreetsAnUnnamedReservedAccountWithoutAName()
    {
        var content = Template("https://app.example.com/invite?token={token}").Build(User(), "raw-token-123");

        await Assert.That(content.PlainTextBody).Contains("Hi there,");
    }
}
