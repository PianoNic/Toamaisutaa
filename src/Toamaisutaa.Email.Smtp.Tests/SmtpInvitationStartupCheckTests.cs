using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpInvitationStartupCheckTests
{
    private static ToamaisutaaSmtpEmailOptions Valid() => new()
    {
        Host = "smtp.example.com",
        Port = 587,
        From = "noreply@example.com",
        InvitationLinkTemplate = "https://app.example.com/invite?token={token}",
    };

    private static SmtpInvitationStartupCheck Check(ToamaisutaaSmtpEmailOptions options, IInvitationEmailTemplate? template = null) =>
        new(Options.Create(options), template ?? new DefaultInvitationEmailTemplate(Options.Create(options)));

    [Test]
    public async Task ValidOptionsStartCleanly()
    {
        await Check(Valid()).StartAsync(CancellationToken.None);
    }

    [Test]
    public async Task RefusesToStartWithNoInvitationLinkTemplate()
    {
        var options = Valid();
        options.InvitationLinkTemplate = null;

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWhenTheInvitationLinkTemplateHasNoTokenPlaceholder()
    {
        var options = Valid();
        options.InvitationLinkTemplate = "https://app.example.com/invite";

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    // The link is the default template's business alone, so a consumer template is not held to it.
    [Test]
    public async Task StartsCleanlyWithoutALinkTemplateWhenTheTemplateIsNotTheDefault()
    {
        var options = Valid();
        options.InvitationLinkTemplate = null;

        await Check(options, new FakeInvitationEmailTemplate()).StartAsync(CancellationToken.None);
    }
}
