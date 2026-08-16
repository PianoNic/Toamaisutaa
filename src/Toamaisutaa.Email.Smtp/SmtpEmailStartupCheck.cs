using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Refuses to start rather than failing on the first password reset request, the same
/// reasoning <c>PasswordLoginStartupCheck</c> uses for local login.</summary>
internal sealed class SmtpEmailStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    ILogger<SmtpEmailStartupCheck> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        if (string.IsNullOrWhiteSpace(settings.Host))
            problems.Add("Email:Smtp:Host is not set.");

        if (settings.Port is <= 0 or > 65535)
            problems.Add($"Email:Smtp:Port is {settings.Port}, which is not a valid port number.");

        if (string.IsNullOrWhiteSpace(settings.From) || !MailboxAddress.TryParse(settings.From, out _))
            problems.Add("Email:Smtp:From is not set or is not a valid email address.");

        if (string.IsNullOrWhiteSpace(settings.PasswordResetLinkTemplate))
        {
            problems.Add(
                "Email:Smtp:PasswordResetLinkTemplate is not set. The default template needs it to build the link "
                + "the reset email points at - or register your own IPasswordResetEmailTemplate that does not need it.");
        }
        else if (!settings.PasswordResetLinkTemplate.Contains("{token}", StringComparison.Ordinal))
        {
            problems.Add("Email:Smtp:PasswordResetLinkTemplate does not contain \"{token}\", so every reset link would point at the same place.");
        }

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP email is registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        if (settings.SkipCertificateVerification)
            logger.LogWarning("Email:Smtp:SkipCertificateVerification is on - the SMTP server's TLS certificate is not being checked.");

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
