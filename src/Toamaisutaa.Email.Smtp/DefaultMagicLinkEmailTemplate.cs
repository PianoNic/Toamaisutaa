using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording, the same as the reset email - and one extra line, because
/// this is the only message this package sends that signs somebody in by itself.</summary>
/// <remarks>
/// The expiry in the text is read from <see cref="ToamaisutaaLocalLoginOptions.MagicLinkTokenLifetime"/>
/// rather than from a setting of its own. Two settings that have to agree eventually stop agreeing,
/// and the one that would be wrong is the one in front of the person waiting for the link.
/// </remarks>
internal sealed class DefaultMagicLinkEmailTemplate(
    IOptions<ToamaisutaaSmtpEmailOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin) : IMagicLinkEmailTemplate
{
    public MagicLinkEmailContent Build(ToamaisutaaUser user, string magicLinkToken)
    {
        var link = BuildLink(magicLinkToken);
        var name = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;
        var minutes = (int)Math.Ceiling(localLogin.Value.MagicLinkTokenLifetime.TotalMinutes);

        // The "do not forward" line earns its place: every other link this package sends leads to a
        // form that asks for something else first, and this one does not.
        return new MagicLinkEmailContent
        {
            Subject = "Your sign-in link",
            PlainTextBody =
                $"""
                Hi {name},

                Use the link below to sign in. It works once, and it expires in about {minutes} minutes:

                {link}

                Anyone who opens this link is signed in as you, so do not forward it. If you did not ask to sign in,
                you can ignore this email.
                """,
            HtmlBody =
                $"""
                <p>Hi {System.Net.WebUtility.HtmlEncode(name)},</p>
                <p>Use the link below to sign in. It works once, and it expires in about {minutes} minutes:</p>
                <p><a href="{System.Net.WebUtility.HtmlEncode(link)}">{System.Net.WebUtility.HtmlEncode(link)}</a></p>
                <p>Anyone who opens this link is signed in as you, so do not forward it. If you did not ask to sign in,
                you can ignore this email.</p>
                """,
        };
    }

    private string BuildLink(string magicLinkToken)
    {
        var template = options.Value.MagicLinkTemplate;

        // Validated at startup, so this is only reachable if the option was never set - which is
        // itself a caller error, since the default template cannot invent a page it knows nothing
        // about. A missing link is better than a wrong one.
        if (string.IsNullOrWhiteSpace(template))
            throw new InvalidOperationException("Email:Smtp:MagicLinkTemplate is not set.");

        return template.Replace("{token}", Uri.EscapeDataString(magicLinkToken), StringComparison.Ordinal);
    }
}
