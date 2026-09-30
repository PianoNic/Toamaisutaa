using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

internal sealed class DefaultInvitationEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IInvitationEmailTemplate
{
    public InvitationEmailContent Build(ToamaisutaaUser user, string invitationToken)
    {
        var link = LinkTemplates.Build(
            options.Value.InvitationLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.InvitationLinkTemplate),
            invitationToken);

        // A reserved row has neither a user name nor a display name until the invitation is
        // completed, so this greeting is usually the unnamed one.
        var name = Greeting.NameOf(user);

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
}
