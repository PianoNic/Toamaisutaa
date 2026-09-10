using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpEmailVerificationStartupCheckTests
{
    private static ToamaisutaaSmtpEmailOptions Valid() => new()
    {
        Host = "smtp.example.com",
        Port = 587,
        From = "noreply@example.com",
        EmailVerificationLinkTemplate = "https://app.example.com/verify?token={token}",
    };

    private static SmtpEmailVerificationStartupCheck Check(ToamaisutaaSmtpEmailOptions options, IEmailVerificationEmailTemplate? template = null) =>
        new(Options.Create(options), template ?? new DefaultEmailVerificationEmailTemplate(Options.Create(options)));

    [Test]
    public async Task ValidOptionsStartCleanly()
    {
        await Check(Valid()).StartAsync(CancellationToken.None);
    }

    [Test]
    public async Task RefusesToStartWithNoVerificationLinkTemplate()
    {
        var options = Valid();
        options.EmailVerificationLinkTemplate = null;

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWhenTheVerificationLinkTemplateHasNoTokenPlaceholder()
    {
        var options = Valid();
        options.EmailVerificationLinkTemplate = "https://app.example.com/verify";

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    // The link is the default template's business alone, so a consumer template is not held to it.
    [Test]
    public async Task StartsCleanlyWithoutALinkTemplateWhenTheTemplateIsNotTheDefault()
    {
        var options = Valid();
        options.EmailVerificationLinkTemplate = null;

        await Check(options, new FakeEmailVerificationEmailTemplate()).StartAsync(CancellationToken.None);
    }
}
