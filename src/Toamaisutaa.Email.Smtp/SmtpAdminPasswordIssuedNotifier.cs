using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The one implementation of <see cref="IAdminPasswordIssuedNotifier"/> this repository ships.
/// Builds the message from <see cref="IAdminPasswordIssuedEmailTemplate"/> and hands it to
/// <see cref="ISmtpMessageSender"/>.
/// </summary>
/// <remarks>
/// Never logs the password, the same rule the enrolment response follows elsewhere in this package:
/// a log line is forever, and this one is a credential.
/// </remarks>
internal sealed class SmtpAdminPasswordIssuedNotifier(
    IAdminPasswordIssuedEmailTemplate template,
    ISmtpMessageSender sender,
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpAdminPasswordIssuedNotifier> logger) : IAdminPasswordIssuedNotifier
{
    public async Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(rawPassword);

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            // The account now has a password nobody has been told, so this is a warning and not an
            // observation: the caller has to set another one, or the account is unreachable.
            logger.LogWarning(
                "Password email skipped for user {UserId}: the account has no email address, so the issued password was not delivered anywhere.",
                user.Id);
            return;
        }

        var content = template.Build(user, rawPassword);
        var settings = options.Value;

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings.FromDisplayName ?? string.Empty, settings.From));
        message.To.Add(new MailboxAddress(user.DisplayName ?? user.Email, user.Email));
        message.Subject = content.Subject;

        var body = new BodyBuilder { TextBody = content.PlainTextBody, HtmlBody = content.HtmlBody };
        message.Body = body.ToMessageBody();

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Password email sent to user {UserId}.", user.Id);
    }
}
