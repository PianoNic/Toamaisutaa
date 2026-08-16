using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns a reset token into the email that gets sent. Register your own and it replaces the default
/// outright - the same seam <c>IPasswordValidator</c> and <c>IPasswordHasher</c> use elsewhere in
/// this package.
/// </summary>
public interface IPasswordResetEmailTemplate
{
    /// <summary>
    /// Called with the raw token - the only moment it exists in the clear. Put it in the link;
    /// nothing downstream of this call logs it.
    /// </summary>
    PasswordResetEmailContent Build(ToamaisutaaUser user, string resetToken);
}

/// <summary>The subject and body <see cref="SmtpPasswordResetNotifier"/> sends. <see cref="HtmlBody"/>
/// is optional - omit it for a plaintext-only email.</summary>
public sealed record PasswordResetEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
