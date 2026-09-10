using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp.Tests;

public class SmtpMagicLinkStartupCheckTests
{
    private static ToamaisutaaSmtpEmailOptions Valid() => new()
    {
        Host = "smtp.example.com",
        Port = 587,
        From = "noreply@example.com",
        MagicLinkTemplate = "https://app.example.com/signin?token={token}",
    };

    private static SmtpMagicLinkStartupCheck Check(ToamaisutaaSmtpEmailOptions options, IMagicLinkEmailTemplate? template = null) =>
        new(
            Options.Create(options),
            template ?? new DefaultMagicLinkEmailTemplate(Options.Create(options), Options.Create(new ToamaisutaaLocalLoginOptions())));

    [Test]
    public async Task ValidOptionsStartCleanly()
    {
        await Check(Valid()).StartAsync(CancellationToken.None);
    }

    [Test]
    public async Task RefusesToStartWithNoMagicLinkTemplate()
    {
        var options = Valid();
        options.MagicLinkTemplate = null;

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RefusesToStartWhenTheMagicLinkTemplateHasNoTokenPlaceholder()
    {
        var options = Valid();
        options.MagicLinkTemplate = "https://app.example.com/signin";

        await Assert.That(() => Check(options).StartAsync(CancellationToken.None)).Throws<InvalidOperationException>();
    }

    // The link is the default template's business alone, so a consumer template is not held to it.
    [Test]
    public async Task StartsCleanlyWithoutALinkTemplateWhenTheTemplateIsNotTheDefault()
    {
        var options = Valid();
        options.MagicLinkTemplate = null;

        await Check(options, new FakeMagicLinkEmailTemplate()).StartAsync(CancellationToken.None);
    }
}
