using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

internal sealed class DefaultEmailVerificationEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IEmailVerificationEmailTemplate
{
    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken) =>
        Build(user, email, verificationToken, new EmailVerificationContext());

    public EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken, EmailVerificationContext context)
    {
        var link = LinkTemplates.Build(
            options.Value.EmailVerificationLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.EmailVerificationLinkTemplate),
            verificationToken);

        // No name: it is attacker-chosen text, and this goes to an unproven address, so greeting by it
        // would let anyone mail their own words from this domain to any inbox. The warning names nobody
        // either, for the same reason.
        if (context.TakesFromAnotherAccount)
        {
            return new EmailVerificationEmailContent
            {
                Subject = "Someone wants to move your email address to their account",
                PlainTextBody =
                    $"""
                    Hi,

                    Someone asked to use {email} on their account. It is currently on another account here,
                    which may be yours. Using the link below moves it away from that account to theirs.

                    Only use it if you asked for this yourself:

                    {link}

                    If you did not ask for this, do not use the link. Nothing changes until it is used.
                    """,
                HtmlBody =
                    $"""
                    <p>Hi,</p>
                    <p>Someone asked to use {System.Net.WebUtility.HtmlEncode(email)} on their account. It is currently on another account here, which may be yours. Using the link below moves it away from that account to theirs.</p>
                    <p>Only use it if you asked for this yourself:</p>
                    <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                    <p>If you did not ask for this, do not use the link. Nothing changes until it is used.</p>
                    """,
            };
        }

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
