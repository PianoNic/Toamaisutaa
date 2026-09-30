using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

internal sealed class SmtpMagicLinkStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IMagicLinkEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // A consumer template may build its own link, or none, so only the default needs the option.
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
