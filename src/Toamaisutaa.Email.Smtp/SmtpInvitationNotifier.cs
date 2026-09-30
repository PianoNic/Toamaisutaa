using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Never logs the token or the link: a log line is forever, and this one is a credential.</summary>
internal sealed class SmtpInvitationNotifier(
    IInvitationEmailTemplate template,
    ISmtpMessageSender sender,
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpInvitationNotifier> logger) : IInvitationNotifier
{
    public async Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(invitationToken);

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            logger.LogWarning("Invitation email skipped for user {UserId}: the account has no email address.", user.Id);
            return;
        }

        var content = template.Build(user, invitationToken);
        var message = SmtpMessages.Create(options.Value, user.Email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Invitation email sent to user {UserId}.", user.Id);
    }
}
