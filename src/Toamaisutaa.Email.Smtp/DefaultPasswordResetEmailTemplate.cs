using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

internal sealed class DefaultPasswordResetEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IPasswordResetEmailTemplate
{
    public PasswordResetEmailContent Build(ToamaisutaaUser user, string resetToken)
    {
        var link = LinkTemplates.Build(
            options.Value.PasswordResetLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.PasswordResetLinkTemplate),
            resetToken);

        // No name: it is attacker-chosen text, and the address may never have been proven.
        return new PasswordResetEmailContent
        {
            Subject = "Reset your password",
            PlainTextBody =
                $"""
                Hi,

                A password reset was requested for your account. Use the link below to choose a new password:

                {link}

                If you did not request this, you can ignore this email.
                """,
            HtmlBody =
                $"""
                <p>Hi,</p>
                <p>A password reset was requested for your account. Use the link below to choose a new password:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>If you did not request this, you can ignore this email.</p>
                """,
        };
    }
}
