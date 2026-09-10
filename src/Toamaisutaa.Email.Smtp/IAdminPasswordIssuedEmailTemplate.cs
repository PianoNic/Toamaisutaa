using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns a password an admin caused to exist into the email that gets sent. Register your own and
/// it replaces the default outright - the same seam <see cref="IPasswordResetEmailTemplate"/>
/// offers for the reset email.
/// </summary>
public interface IAdminPasswordIssuedEmailTemplate
{
    /// <summary>
    /// Called with the raw password - the only moment it exists in the clear. Put it in the body;
    /// nothing downstream of this call logs it.
    /// </summary>
    AdminPasswordIssuedEmailContent Build(ToamaisutaaUser user, string rawPassword);
}

/// <summary>The subject and body <see cref="SmtpAdminPasswordIssuedNotifier"/> sends.
/// <see cref="HtmlBody"/> is optional - omit it for a plaintext-only email.</summary>
public sealed record AdminPasswordIssuedEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
