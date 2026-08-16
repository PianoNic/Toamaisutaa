using MimeKit;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Wraps the actual SMTP connection, so <see cref="SmtpPasswordResetNotifier"/> can be
/// tested without one.</summary>
internal interface ISmtpMessageSender
{
    Task SendAsync(MimeMessage message, CancellationToken cancellationToken);
}
