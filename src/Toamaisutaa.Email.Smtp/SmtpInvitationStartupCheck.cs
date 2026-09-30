using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

internal sealed class SmtpInvitationStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IInvitationEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // A consumer template may build its own link, or none, so only the default needs the option.
        if (template is not DefaultInvitationEmailTemplate)
            return Task.CompletedTask;

        var problem = LinkTemplates.Problem(
            options.Value.InvitationLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.InvitationLinkTemplate),
            "invitation",
            nameof(IInvitationEmailTemplate));

        if (problem is not null)
            throw StartupProblems.Refusal("Toamaisutaa SMTP invitation email is registered but not usable:", [problem]);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
