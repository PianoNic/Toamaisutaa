using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Never logs the token or the link: a log line is forever, and this one is a credential.</summary>
internal sealed class SmtpPasswordResetNotifier(
    IPasswordResetEmailTemplate template,
    ISmtpMessageSender sender,
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpPasswordResetNotifier> logger) : IPasswordResetNotifier
{
    public async Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(resetToken);

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            logger.LogWarning("Password reset email skipped for user {UserId}: the account has no email address.", user.Id);
            return;
        }

        var content = template.Build(user, resetToken);
        var message = SmtpMessages.Create(options.Value, user.Email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Password reset email sent to user {UserId}.", user.Id);
    }
}
