using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Addressed to the email it is handed, not the user row's, because a change of address is
/// proven by mail only the new mailbox receives. Never logs the token or link.</summary>
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
        var message = SmtpMessages.Create(options.Value, email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Email verification sent for user {UserId}.", user.Id);
    }
}
