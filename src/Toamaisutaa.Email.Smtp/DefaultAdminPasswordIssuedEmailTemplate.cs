using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>Plain, utilitarian wording, the same as the reset email. One message covers both admin
/// paths, because the notifier is handed a password and a user and cannot tell a freshly created
/// account from one whose password was overwritten.</summary>
internal sealed class DefaultAdminPasswordIssuedEmailTemplate(IOptions<ToamaisutaaSmtpEmailOptions> options) : IAdminPasswordIssuedEmailTemplate
{
    private const string Preamble = "An administrator set a password on your account. Sign in with it and change it straight away.";

    public AdminPasswordIssuedEmailContent Build(ToamaisutaaUser user, string rawPassword)
    {
        var name = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserName ?? "there" : user.DisplayName;
        var userName = user.UserName;
        var signInUrl = options.Value.SignInUrl;

        var plainCredentials = string.IsNullOrWhiteSpace(userName)
            ? $"Password: {rawPassword}"
            : $"User name: {userName}{Environment.NewLine}Password: {rawPassword}";

        var plainSignIn = string.IsNullOrWhiteSpace(signInUrl)
            ? string.Empty
            : $"{Environment.NewLine}{Environment.NewLine}Sign in at {signInUrl}";

        // Encoded because a generated password is a random string that may well contain & or <, and
        // an email client that renders it as markup shows the wrong password with no sign of it.
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
