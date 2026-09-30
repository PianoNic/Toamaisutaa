using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Refuses to start rather than failing on the first verification, the same reasoning
/// <see cref="SmtpEmailStartupCheck"/> uses for the transport. Registered only by
/// <c>AddToamaisutaaSmtpEmailVerification</c>, so an application that never verifies an address is
/// never held to a verification link.</summary>
internal sealed class SmtpEmailVerificationStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IEmailVerificationEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // The link is the default template's business alone. A consumer template that builds its
        // own, or none at all, has no reason to configure one.
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
