using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Refuses to start rather than failing on the first verification, the same reasoning
/// <see cref="SmtpEmailStartupCheck"/> uses for the transport. Registered only by
/// <c>AddToamaisutaaSmtpEmailVerification</c>, so an application that never verifies an address is
/// never held to a verification link.</summary>
internal sealed class SmtpEmailVerificationStartupCheck(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IEmailVerificationEmailTemplate template) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // The link is the default template's business alone. A consumer template that builds its
        // own, or none at all, has no reason to configure one.
        if (template is not DefaultEmailVerificationEmailTemplate)
            return Task.CompletedTask;

        var linkTemplate = options.Value.EmailVerificationLinkTemplate;

        if (string.IsNullOrWhiteSpace(linkTemplate))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP email verification is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:EmailVerificationLinkTemplate is not set. The default template needs it to build the "
                + "link the verification email points at - or register your own IEmailVerificationEmailTemplate that "
                + "does not need it.");
        }

        if (!linkTemplate.Contains("{token}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Toamaisutaa SMTP email verification is registered but not usable:"
                + Environment.NewLine
                + "  - Email:Smtp:EmailVerificationLinkTemplate does not contain \"{token}\", so every verification link "
                + "would point at the same place.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
