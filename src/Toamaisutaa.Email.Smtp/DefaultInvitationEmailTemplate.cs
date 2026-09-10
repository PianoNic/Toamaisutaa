using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording, the same as the reset email - an invitation link is the one
/// thing standing between a stranger and an account, not the place for this package's usual
/// voice.</summary>
internal sealed class DefaultInvitationEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IInvitationEmailTemplate
{
    public InvitationEmailContent Build(ToamaisutaaUser user, string invitationToken)
    {
        var link = BuildLink(invitationToken);

        // A reserved row has neither a user name nor a display name until the invitation is
        // completed, so this greeting is usually the unnamed one.
        var name = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;

        return new InvitationEmailContent
        {
            Subject = "Finish setting up your account",
            PlainTextBody =
                $"""
                Hi {name},

                An account has been reserved for you. Use the link below to choose a user name and password:

                {link}

                If you were not expecting this, you can ignore this email.
                """,
            HtmlBody =
                $"""
                <p>Hi {System.Net.WebUtility.HtmlEncode(name)},</p>
                <p>An account has been reserved for you. Use the link below to choose a user name and password:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>If you were not expecting this, you can ignore this email.</p>
                """,
        };
    }

    private string BuildLink(string invitationToken)
    {
        var template = options.Value.InvitationLinkTemplate;

        // Validated at startup, so this is only reachable if the option was never set - which is
        // itself a caller error, since the default template cannot invent a page it knows nothing
        // about. A missing link is better than a wrong one.
        if (string.IsNullOrWhiteSpace(template))
            throw new InvalidOperationException("Email:Smtp:InvitationLinkTemplate is not set.");

        return template.Replace("{token}", Uri.EscapeDataString(invitationToken), StringComparison.Ordinal);
    }
}
