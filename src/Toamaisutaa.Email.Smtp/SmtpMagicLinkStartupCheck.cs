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

        var problem = LinkTemplates.Problem(
            options.Value.MagicLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.MagicLinkTemplate),
            "sign-in",
            nameof(IMagicLinkEmailTemplate));

        if (problem is not null)
            throw StartupProblems.Refusal("Toamaisutaa SMTP magic-link email is registered but not usable:", [problem]);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
