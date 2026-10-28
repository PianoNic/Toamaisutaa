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
    public Task SendAsync(
        ToamaisutaaUser user,
        string email,
        string verificationToken,
        CancellationToken cancellationToken = default) =>
        SendAsync(user, email, verificationToken, new EmailVerificationContext(), cancellationToken);

    public async Task SendAsync(
        ToamaisutaaUser user,
        string email,
        string verificationToken,
        EmailVerificationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(verificationToken);
        ArgumentNullException.ThrowIfNull(context);

        var content = template.Build(user, email, verificationToken, context);
        var message = SmtpMessages.Create(options.Value, email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Email verification sent for user {UserId}.", user.Id);
    }

    public async Task SendAddressInUseAsync(ToamaisutaaUser requester, string email, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requester);
        ArgumentNullException.ThrowIfNull(email);

        var content = template.BuildAddressInUse(requester, email);
        var message = SmtpMessages.Create(options.Value, email, content.Subject, content.PlainTextBody, content.HtmlBody);

        await sender.SendAsync(message, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Address-in-use notice sent for an email change asked by user {UserId}.", requester.Id);
    }
}
