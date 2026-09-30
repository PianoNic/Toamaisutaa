using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Never logs the token or the link: the link is a session in itself.</summary>
internal sealed class SmtpMagicLinkNotifier(
    IMagicLinkEmailTemplate template,
    ISmtpMessageSender sender,
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpMagicLinkNotifier> logger) : IMagicLinkNotifier
{
    public async Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(magicLinkToken);

        if (string.IsNullOrWhiteSpace(user.Email))
        {
            logger.LogWarning("Magic-link email skipped for user {UserId}: the account has no email address.", user.Id);
            return;
        }

        var content = template.Build(user, magicLinkToken);
        var message = SmtpMessages.Create(options.Value, user.Email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Magic-link email sent to user {UserId}.", user.Id);
    }
}
