using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns a verification token into the email that gets sent. Register your own to replace the
/// default.
/// </summary>
public interface IEmailVerificationEmailTemplate
{
    /// <summary>
    /// Called with the raw token - the only moment it exists in the clear. Put it in the link;
    /// nothing downstream of this call logs it.
    /// </summary>
    /// <remarks>
    /// <c>email</c> is the address being verified, and is where the message goes. It is not
    /// <see cref="ToamaisutaaUser.Email"/> whenever somebody is moving to a new one.
    /// </remarks>
    EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken);

    /// <summary>
    /// The same, with what the message has to warn about. The default drops the context; implement it
    /// so the mail says when the link takes the address from another account.
    /// </summary>
    EmailVerificationEmailContent Build(ToamaisutaaUser user, string email, string verificationToken, EmailVerificationContext context) =>
        Build(user, email, verificationToken);

    /// <summary>
    /// To the owner of an address another account asked for, which this one has already proven. No
    /// link, and no name: the asker chose their user name.
    /// </summary>
    EmailVerificationEmailContent BuildAddressInUse(ToamaisutaaUser requester, string email) => new()
    {
        Subject = "Someone tried to use your email address",
        PlainTextBody =
            "Hi,\n\n"
            + $"Someone tried to add {email} to their account here. It is already on an account, so nothing was "
            + "changed and no link was sent.\n\n"
            + "If that was you, you already have an account with this address: sign in to it, or reset its password.\n",
        HtmlBody =
            "<p>Hi,</p>"
            + $"<p>Someone tried to add {System.Net.WebUtility.HtmlEncode(email)} to their account here. It is already on an "
            + "account, so nothing was changed and no link was sent.</p>"
            + "<p>If that was you, you already have an account with this address: sign in to it, or reset its password.</p>",
    };

    /// <summary>
    /// The code that confirms <paramref name="email"/> before an account signs in, with
    /// <c>LocalLogin:RequireVerifiedEmailForSignIn</c> on. Implement it for your own wording; the code is
    /// in the clear only here, so nothing downstream logs it.
    /// </summary>
    /// <remarks>
    /// No name, as in the link mails: it is whatever the registrant typed, and this goes to an address
    /// nobody has proven yet.
    /// </remarks>
    EmailVerificationEmailContent BuildCode(ToamaisutaaUser user, string email, string code, TimeSpan validFor) => new()
    {
        Subject = $"Your verification code is {code}",
        PlainTextBody =
            "Hi,\n\n"
            + $"Your verification code is {code}\n\n"
            + $"Enter it to confirm that {email} belongs to your account. It works for {Duration(validFor)}.\n\n"
            + "If you did not sign up or sign in, you can ignore this email.\n",
        HtmlBody =
            "<p>Hi,</p>"
            + $"<p>Your verification code is <strong style=\"font-size:1.5em;letter-spacing:0.15em\">{code}</strong></p>"
            + $"<p>Enter it to confirm that {System.Net.WebUtility.HtmlEncode(email)} belongs to your account. It works for {Duration(validFor)}.</p>"
            + "<p>If you did not sign up or sign in, you can ignore this email.</p>",
    };

    private static string Duration(TimeSpan period) => period.TotalMinutes < 1
        ? $"{Math.Ceiling(period.TotalSeconds)} seconds"
        : period.TotalHours < 1
            ? Math.Ceiling(period.TotalMinutes) is 1 ? "1 minute" : $"{Math.Ceiling(period.TotalMinutes)} minutes"
            : Math.Ceiling(period.TotalHours) is 1 ? "1 hour" : $"{Math.Ceiling(period.TotalHours)} hours";
}

/// <summary>The subject and body <see cref="SmtpEmailVerificationNotifier"/> sends.
/// <see cref="HtmlBody"/> is optional - omit it for a plaintext-only email.</summary>
public sealed record EmailVerificationEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
