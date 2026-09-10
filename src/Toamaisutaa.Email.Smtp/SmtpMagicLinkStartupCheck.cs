using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Refuses to start rather than failing on the first sign-in link, the same reasoning
/// <see cref="SmtpEmailStartupCheck"/> uses for the transport. Registered only by
/// <c>AddToamaisutaaSmtpMagicLink</c>, so an application that never sends one is never held to a
/// sign-in link.</summary>
internal sealed class SmtpMagicLinkStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IMagicLinkEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // The link is the default template's business alone. A consumer template that builds its
        // own, or none at all, has no reason to configure one.
        if (template is not DefaultMagicLinkEmailTemplate)
            return Task.CompletedTask;

        var linkTemplate = options.Value.MagicLinkTemplate;

        if (string.IsNullOrWhiteSpace(linkTemplate))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP magic-link email is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:MagicLinkTemplate is not set. The default template needs it to build the link the "
                + "sign-in email points at - or register your own IMagicLinkEmailTemplate that does not need it.");
        }

        if (!linkTemplate.Contains("{token}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP magic-link email is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:MagicLinkTemplate does not contain \"{token}\", so every sign-in link would point at "
                + "the same place.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
