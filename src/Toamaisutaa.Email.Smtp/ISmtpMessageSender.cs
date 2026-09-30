using MimeKit;

namespace Toamaisutaa.Email.Smtp;

internal interface ISmtpMessageSender
{
    Task SendAsync(MimeMessage message, CancellationToken cancellationToken);
}
