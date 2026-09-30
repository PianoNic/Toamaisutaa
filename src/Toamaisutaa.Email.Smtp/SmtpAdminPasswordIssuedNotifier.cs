using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Never logs the password: a log line is forever, and this one is a credential.</summary>
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
            // A warning, because the account now has a password nobody has been told.
            logger.LogWarning(
                "Password email skipped for user {UserId}: the account has no email address, so the issued password was not delivered anywhere.",
                user.Id);
            return;
        }

        var content = template.Build(user, rawPassword);
        var message = SmtpMessages.Create(options.Value, user.Email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Password email sent to user {UserId}.", user.Id);
    }
}
