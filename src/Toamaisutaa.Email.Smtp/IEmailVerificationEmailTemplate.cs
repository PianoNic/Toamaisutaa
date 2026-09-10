using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns a verification token into the email that gets sent. Register your own and it replaces the
/// default outright - the same seam <see cref="IPasswordResetEmailTemplate"/> offers for the reset
/// email.
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
}

/// <summary>The subject and body <see cref="SmtpEmailVerificationNotifier"/> sends.
/// <see cref="HtmlBody"/> is optional - omit it for a plaintext-only email.</summary>
public sealed record EmailVerificationEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
