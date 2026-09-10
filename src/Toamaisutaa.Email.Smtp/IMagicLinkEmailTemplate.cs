using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Turns a magic-link token into the email that gets sent. Register your own and it replaces the
/// default outright - the same seam <see cref="IPasswordResetEmailTemplate"/> offers for the reset
/// email.
/// </summary>
public interface IMagicLinkEmailTemplate
{
    /// <summary>
    /// Called with the raw token - the only moment it exists in the clear. Put it in the link;
    /// nothing downstream of this call logs it.
    /// </summary>
    /// <remarks>
    /// This link signs somebody in on its own, which no other message this package sends does. Say
    /// so in the wording, and keep it out of anything that renders mail into a shared view.
    /// </remarks>
    MagicLinkEmailContent Build(ToamaisutaaUser user, string magicLinkToken);
}

/// <summary>The subject and body <see cref="SmtpMagicLinkNotifier"/> sends.
/// <see cref="HtmlBody"/> is optional - omit it for a plaintext-only email.</summary>
public sealed record MagicLinkEmailContent
{
    public required string Subject { get; init; }

    public required string PlainTextBody { get; init; }

    public string? HtmlBody { get; init; }
}
