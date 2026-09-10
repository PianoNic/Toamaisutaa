using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The one implementation of <see cref="IEmailVerificationNotifier"/> this repository ships. Builds
/// the message from <see cref="IEmailVerificationEmailTemplate"/> and hands it to
/// <see cref="ISmtpMessageSender"/>.
/// </summary>
/// <remarks>
/// Addressed to the email it is handed rather than to the one on the user row, which is the whole
/// mechanism: a change of address is proven by mail that only the new mailbox receives. Never logs
/// the token or the link it appears in, the same rule the other notifiers here follow.
/// </remarks>
internal sealed class SmtpEmailVerificationNotifier(
    IEmailVerificationEmailTemplate template,
    ISmtpMessageSender sender,
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpEmailVerificationNotifier> logger) : IEmailVerificationNotifier
{
    public async Task SendAsync(
        ToamaisutaaUser user,
        string email,
        string verificationToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(verificationToken);

        var content = template.Build(user, email, verificationToken);
        var settings = options.Value;

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings.FromDisplayName ?? string.Empty, settings.From));
        message.To.Add(new MailboxAddress(user.DisplayName ?? email, email));
        message.Subject = content.Subject;

        var body = new BodyBuilder { TextBody = content.PlainTextBody, HtmlBody = content.HtmlBody };
        message.Body = body.ToMessageBody();

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Email verification sent for user {UserId}.", user.Id);
    }
}
