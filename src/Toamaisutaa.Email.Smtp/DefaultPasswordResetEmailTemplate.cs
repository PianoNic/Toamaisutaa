using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording - a password reset link is security mail, not the place for
/// this package's usual voice.</summary>
internal sealed class DefaultPasswordResetEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IPasswordResetEmailTemplate
{
    public PasswordResetEmailContent Build(ToamaisutaaUser user, string resetToken)
    {
        var link = BuildLink(resetToken);
        var name = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;

        return new PasswordResetEmailContent
        {
            Subject = "Reset your password",
            PlainTextBody =
                $"""
                Hi {name},

                A password reset was requested for your account. Use the link below to choose a new password:

                {link}

                If you did not request this, you can ignore this email.
                """,
            HtmlBody =
                $"""
                <p>Hi {System.Net.WebUtility.HtmlEncode(name)},</p>
                <p>A password reset was requested for your account. Use the link below to choose a new password:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>If you did not request this, you can ignore this email.</p>
                """,
        };
    }

    private string BuildLink(string resetToken)
    {
        var template = options.Value.PasswordResetLinkTemplate;

        // Validated at startup, so this is only reachable if the option was never set - which is
        // itself a caller error, since the default template cannot invent a page it knows nothing
        // about. A missing link is better than a wrong one.
        if (string.IsNullOrWhiteSpace(template))
            throw new InvalidOperationException("Email:Smtp:PasswordResetLinkTemplate is not set.");

        return template.Replace("{token}", Uri.EscapeDataString(resetToken), StringComparison.Ordinal);
    }
}
