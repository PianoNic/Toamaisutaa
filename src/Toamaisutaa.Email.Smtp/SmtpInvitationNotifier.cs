using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The one implementation of <see cref="IInvitationNotifier"/> this repository ships. Builds the
/// message from <see cref="IInvitationEmailTemplate"/> and hands it to <see cref="ISmtpMessageSender"/>.
/// </summary>
/// <remarks>
/// Never logs the token or the link it appears in, the same rule the enrolment response follows
/// elsewhere in this package: a log line is forever, and this one is a credential.
/// </remarks>
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
        var settings = options.Value;

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings.FromDisplayName ?? string.Empty, settings.From));
        message.To.Add(new MailboxAddress(user.DisplayName ?? user.Email, user.Email));
        message.Subject = content.Subject;

        var body = new BodyBuilder { TextBody = content.PlainTextBody, HtmlBody = content.HtmlBody };
        message.Body = body.ToMessageBody();

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Invitation email sent to user {UserId}.", user.Id);
    }
}
