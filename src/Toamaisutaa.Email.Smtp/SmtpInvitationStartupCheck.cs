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

        var linkTemplate = options.Value.InvitationLinkTemplate;

        if (string.IsNullOrWhiteSpace(linkTemplate))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP invitation email is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:InvitationLinkTemplate is not set. The default template needs it to build the link "
                + "the invitation email points at - or register your own IInvitationEmailTemplate that does not need it.");
        }

        if (!linkTemplate.Contains("{token}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP invitation email is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:InvitationLinkTemplate does not contain \"{token}\", so every invitation link would point at the same place.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
