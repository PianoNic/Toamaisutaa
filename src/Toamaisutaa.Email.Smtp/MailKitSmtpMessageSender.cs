using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Toamaisutaa.Email.Smtp;

internal sealed class MailKitSmtpMessageSender(IOptions<ToamaisutaaSmtpEmailOptions> options) : ISmtpMessageSender
{
    public async Task SendAsync(MimeMessage message, CancellationToken cancellationToken)
    {
        var settings = options.Value;

        using var client = new SmtpClient();
        client.Timeout = (int)settings.Timeout.TotalMilliseconds;

        if (settings.SkipCertificateVerification)
            client.ServerCertificateValidationCallback = (_, _, _, _) => true;

        await client.ConnectAsync(settings.Host!, settings.Port, ToSecureSocketOptions(settings.Security, settings.Port), cancellationToken)
            .ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(settings.User))
            await client.AuthenticateAsync(settings.User, settings.Password ?? string.Empty, cancellationToken).ConfigureAwait(false);

        await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false);
    }

    /// <remarks>
    /// Auto is not MailKit's Auto, whose opportunistic STARTTLS can be stripped on the path to leak the
    /// login and every link in the clear.
    /// </remarks>
    internal static SecureSocketOptions ToSecureSocketOptions(SmtpSecurityMode mode, int port) => mode switch
    {
        SmtpSecurityMode.None => SecureSocketOptions.None,
        SmtpSecurityMode.StartTls => SecureSocketOptions.StartTls,
        SmtpSecurityMode.SslOnConnect => SecureSocketOptions.SslOnConnect,
        _ => port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls,
    };
}
