using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>One message covers both admin paths, because the notifier cannot tell a freshly created
/// account from one whose password was overwritten.</summary>
internal sealed class DefaultAdminPasswordIssuedEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IAdminPasswordIssuedEmailTemplate
{
    private const string Preamble = "An administrator set a password on your account. Sign in with it and change it straight away.";

    public AdminPasswordIssuedEmailContent Build(ToamaisutaaUser user, string rawPassword)
    {
        var name = Greeting.NameOf(user);
        var userName = user.UserName;
        var signInUrl = options.Value.SignInUrl;

        var plainCredentials = string.IsNullOrWhiteSpace(userName)
            ? $"Password: {rawPassword}"
            : $"User name: {userName}{Environment.NewLine}Password: {rawPassword}";

        var plainSignIn = string.IsNullOrWhiteSpace(signInUrl)
            ? string.Empty
            : $"{Environment.NewLine}{Environment.NewLine}Sign in at {signInUrl}";

        // A generated password may contain & or <, and rendered as markup it shows the wrong password.
        var htmlCredentials = string.IsNullOrWhiteSpace(userName)
            ? $"Password: {Encode(rawPassword)}"
            : $"User name: {Encode(userName)}<br />Password: {Encode(rawPassword)}";

        var htmlSignIn = string.IsNullOrWhiteSpace(signInUrl)
            ? string.Empty
            : $"""<p><a href="{Encode(signInUrl)}">{Encode(signInUrl)}</a></p>""";

        return new AdminPasswordIssuedEmailContent
        {
            Subject = "Your new password",
            PlainTextBody =
                $"""
                Hi {name},

                {Preamble}

                {plainCredentials}
                """ + plainSignIn,
            HtmlBody =
                $"""
                <p>Hi {Encode(name)},</p>
                <p>{Preamble}</p>
                <p>{htmlCredentials}</p>
                """ + htmlSignIn,
        };
    }

    private static string Encode(string value) => System.Net.WebUtility.HtmlEncode(value);
}
