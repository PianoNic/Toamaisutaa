using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording, the same as the reset email - a link that decides which
/// mailbox owns an account is security mail, not the place for this package's usual voice.</summary>
internal sealed class DefaultEmailVerificationEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IEmailVerificationEmailTemplate
{
    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken)
    {
        var link = BuildLink(verificationToken);
        var name = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;

        // Naming the address is the whole point of this line: the person reading it is the only one
        // who can tell whether the account should be pointing here at all.
        return new EmailVerificationEmailContent
        {
            Subject = "Verify your email address",
            PlainTextBody =
                $"""
                Hi {name},

                Use the link below to confirm that {email} belongs to your account:

                {link}

                If you did not request this, you can ignore this email. Nothing changes until the link is used.
                """,
            HtmlBody =
                $"""
                <p>Hi {System.Net.WebUtility.HtmlEncode(name)},</p>
                <p>Use the link below to confirm that {System.Net.WebUtility.HtmlEncode(email)} belongs to your account:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>If you did not request this, you can ignore this email. Nothing changes until the link is used.</p>
                """,
        };
    }

    private string BuildLink(string verificationToken)
    {
        var template = options.Value.EmailVerificationLinkTemplate;

        // Validated at startup, so this is only reachable if the option was never set - which is
        // itself a caller error, since the default template cannot invent a page it knows nothing
        // about. A missing link is better than a wrong one.
        if (string.IsNullOrWhiteSpace(template))
            throw new InvalidOperationException("Email:Smtp:EmailVerificationLinkTemplate is not set.");

        return template.Replace("{token}", Uri.EscapeDataString(verificationToken), StringComparison.Ordinal);
    }
}
