using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

internal sealed class SmtpEmailVerificationStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IEmailVerificationEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // A consumer template may build its own link, or none, so only the default needs the option.
        if (template is not DefaultEmailVerificationEmailTemplate)
            return Task.CompletedTask;

        var problem = LinkTemplates.Problem(
            options.Value.EmailVerificationLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.EmailVerificationLinkTemplate),
            "verification",
            nameof(IEmailVerificationEmailTemplate));

        if (problem is not null)
            throw StartupProblems.Refusal("Toamaisutaa SMTP email verification is registered but not usable:", [problem]);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
