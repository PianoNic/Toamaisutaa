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

        var resetLink = LinkTemplates.Problem(
            settings.PasswordResetLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.PasswordResetLinkTemplate),
            "reset",
            nameof(IPasswordResetEmailTemplate));

        if (resetLink is not null)
            problems.Add(resetLink);

        if (problems.Count > 0)
            throw StartupProblems.Refusal("Toamaisutaa SMTP email is registered but not usable:", problems);

        if (settings.SkipCertificateVerification)
            logger.LogWarning("Email:Smtp:SkipCertificateVerification is on - the SMTP server's TLS certificate is not being checked.");

        if (settings.Security == SmtpSecurityMode.None)
        {
            logger.LogWarning(
                "Email:Smtp:Security is None - the SMTP login and every message, reset and magic links included, "
                + "travel unencrypted. Use it only for a relay on the same host.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
