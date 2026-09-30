using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Refuses to start rather than failing on the first invitation, the same reasoning
/// <see cref="SmtpEmailStartupCheck"/> uses for the transport. Registered only by
/// <c>AddToamaisutaaSmtpInvitationEmail</c>, so an application that never sends invitations is
/// never held to an invitation link.</summary>
internal sealed class SmtpInvitationStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IInvitationEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // The link is the default template's business alone. A consumer template that builds its
        // own, or none at all, has no reason to configure one.
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
