using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns an invitation token into the email that gets sent. Register your own and it replaces the
/// default outright - the same seam <see cref="IPasswordResetEmailTemplate"/> offers for the reset
/// email.
/// </summary>
public interface IInvitationEmailTemplate
{
    /// <summary>
    /// Called with the raw token - the only moment it exists in the clear. Put it in the link;
    /// nothing downstream of this call logs it.
    /// </summary>
    InvitationEmailContent Build(ToamaisutaaUser user, string invitationToken);
}

/// <summary>The subject and body <see cref="SmtpInvitationNotifier"/> sends. <see cref="HtmlBody"/>
/// is optional - omit it for a plaintext-only email.</summary>
public sealed record InvitationEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
