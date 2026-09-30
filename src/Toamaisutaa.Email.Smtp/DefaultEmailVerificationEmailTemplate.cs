using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

internal sealed class DefaultEmailVerificationEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IEmailVerificationEmailTemplate
{
    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken)
    {
        var link = LinkTemplates.Build(
            options.Value.EmailVerificationLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.EmailVerificationLinkTemplate),
            verificationToken);

        // No name: it is attacker-chosen text, and this goes to an unproven address, so greeting by it
        // would let anyone mail their own words from this domain to any inbox.
        return new EmailVerificationEmailContent
        {
            Subject = "Verify your email address",
            PlainTextBody =
                $"""
                Hi,

                Use the link below to confirm that {email} belongs to your account:

                {link}

                If you did not request this, you can ignore this email. Nothing changes until the link is used.
                """,
            HtmlBody =
                $"""
                <p>Hi,</p>
                <p>Use the link below to confirm that {System.Net.WebUtility.HtmlEncode(email)} belongs to your account:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>If you did not request this, you can ignore this email. Nothing changes until the link is used.</p>
                """,
        };
    }
}
