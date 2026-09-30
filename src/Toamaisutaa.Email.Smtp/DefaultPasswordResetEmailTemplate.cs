using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording - a password reset link is security mail, not the place for
/// this package's usual voice.</summary>
internal sealed class DefaultPasswordResetEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IPasswordResetEmailTemplate
{
    public PasswordResetEmailContent Build(ToamaisutaaUser user, string resetToken)
    {
        var link = LinkTemplates.Build(
            options.Value.PasswordResetLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.PasswordResetLinkTemplate),
            resetToken);

        // No name. It is whatever the account registered with - a sentence and a URL, if they like -
        // and unless LocalLogin:RequireVerifiedEmailForPasswordReset is on, the address this goes to
        // is one nobody proved. Greeting by it mailed a stranger's words, from this domain, to anyone.
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
