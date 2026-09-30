using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>The expiry in the text is read from <see cref="ToamaisutaaLocalLoginOptions.MagicLinkTokenLifetime"/>
/// rather than a setting of its own, so the two cannot disagree.</summary>
internal sealed class DefaultMagicLinkEmailTemplate(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin) : IMagicLinkEmailTemplate
{
    public MagicLinkEmailContent Build(ToamaisutaaUser user, string magicLinkToken)
    {
        var link = LinkTemplates.Build(
            options.Value.MagicLinkTemplate,
            nameof(ToamaisutaaSmtpEmailOptions.MagicLinkTemplate),
            magicLinkToken);
        var minutes = (int)Math.Ceiling(localLogin.Value.MagicLinkTokenLifetime.TotalMinutes);

        // No name: it is attacker-chosen text, and the address may never have been proven.
        return new MagicLinkEmailContent
        {
            Subject = "Your sign-in link",
            PlainTextBody =
                $"""
                Hi,

                Use the link below to sign in. It works once, and it expires in about {minutes} minutes:

                {link}

                Anyone who opens this link is signed in as you, so do not forward it. If you did not ask to sign in,
                you can ignore this email.
                """,
            HtmlBody =
                $"""
                <p>Hi,</p>
                <p>Use the link below to sign in. It works once, and it expires in about {minutes} minutes:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>Anyone who opens this link is signed in as you, so do not forward it. If you did not ask to sign in,
                you can ignore this email.</p>
                """,
        };
    }
}
