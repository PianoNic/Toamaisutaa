using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Connects fresh for every message rather than pooling. Password reset emails are rare
/// enough that a persistent connection would sit idle far more than it sends.</summary>
internal sealed class MailKitSmtpMessageSender(IOptions<ToamaisutaaSmtpEmailOptions> options) : ISmtpMessageSender
{
    public async Task SendAsync(MimeMessage message, CancellationToken cancellationToken)
    {
        var settings = options.Value;

        using var client = new SmtpClient();
        client.Timeout = (int)settings.Timeout.TotalMilliseconds;

        if (settings.SkipCertificateVerification)
            client.ServerCertificateValidationCallback = (_, _, _, _) => true;

        // SmtpEmailStartupCheck refuses to start with no Host set, so this only runs once it is.
        await client.ConnectAsync(settings.Host!, settings.Port, ToSecureSocketOptions(settings.Security), cancellationToken)
            .ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(settings.User))
            await client.AuthenticateAsync(settings.User, settings.Password ?? string.Empty, cancellationToken).ConfigureAwait(false);

        await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false);
    }

    private static SecureSocketOptions ToSecureSocketOptions(SmtpSecurityMode mode) => mode switch
    {
        SmtpSecurityMode.None => SecureSocketOptions.None,
        SmtpSecurityMode.StartTls => SecureSocketOptions.StartTls,
        SmtpSecurityMode.SslOnConnect => SecureSocketOptions.SslOnConnect,
        _ => SecureSocketOptions.Auto,
    };
}
