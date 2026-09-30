using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// The one implementation of <see cref="IMagicLinkNotifier"/> this repository ships. Builds the
/// message from <see cref="IMagicLinkEmailTemplate"/> and hands it to <see cref="ISmtpMessageSender"/>.
/// </summary>
/// <remarks>
/// Never logs the token or the link it appears in, the same rule every other notifier here follows -
/// and the rule matters most on this one, because the link is a session rather than a step towards
/// getting one.
/// </remarks>
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
