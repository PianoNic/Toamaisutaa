namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Everything read from the <c>Email:Smtp</c> configuration section: the SMTP transport and the
/// links the emails point at.
/// </summary>
public sealed class ToamaisutaaSmtpEmailOptions
{
    public string? Host { get; set; }

    public int Port { get; set; } = 587;

    public string? User { get; set; }

    public string? Password { get; set; }

    /// <summary>How the connection is secured. <see cref="SmtpSecurityMode.Auto"/> picks TLS for
    /// port 465 and required STARTTLS for everything else.</summary>
    public SmtpSecurityMode Security { get; set; } = SmtpSecurityMode.Auto;

    /// <summary>
    /// Skips validating the server's TLS certificate. For a self-signed relay on a private network
    /// only - off by default, and startup logs a warning when it is on.
    /// </summary>
    public bool SkipCertificateVerification { get; set; }

    public string From { get; set; } = string.Empty;

    public string? FromDisplayName { get; set; }

    /// <summary>
    /// The reset link, with <c>{token}</c> replaced by the raw token. Read only by the default
    /// <see cref="IPasswordResetEmailTemplate"/>.
    /// </summary>
    public string? PasswordResetLinkTemplate { get; set; }

    /// <summary>
    /// The invitation link, with <c>{token}</c> replaced by the raw token. Required only when
    /// <c>AddToamaisutaaSmtpInvitationEmail</c> is called and the default
    /// <see cref="IInvitationEmailTemplate"/> is the one in use.
    /// </summary>
    public string? InvitationLinkTemplate { get; set; }

    /// <summary>
    /// The verification link, with <c>{token}</c> replaced by the raw token. Required only when
    /// <c>AddToamaisutaaSmtpEmailVerification</c> is called and the default
    /// <see cref="IEmailVerificationEmailTemplate"/> is the one in use.
    /// </summary>
    public string? EmailVerificationLinkTemplate { get; set; }

    /// <summary>
    /// The sign-in link, with <c>{token}</c> replaced by the raw token. Required only when
    /// <c>AddToamaisutaaSmtpMagicLink</c> is called and the default
    /// <see cref="IMagicLinkEmailTemplate"/> is the one in use.
    /// </summary>
    /// <remarks>
    /// Point it at a page of yours that posts the token to <c>/auth/magic-link/verify</c>. The link
    /// itself is the credential, so keep the page off anything that logs query strings.
    /// </remarks>
    public string? MagicLinkTemplate { get; set; }

    /// <summary>
    /// Where someone signs in, put at the end of the admin-issued password email. Optional.
    /// </summary>
    public string? SignInUrl { get; set; }

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>How <see cref="ToamaisutaaSmtpEmailOptions.Security"/> secures the connection.</summary>
public enum SmtpSecurityMode
{
    /// <summary>TLS on connect for port 465, required STARTTLS otherwise. Unlike MailKit's own Auto,
    /// a server that does not offer STARTTLS is refused.</summary>
    Auto,

    /// <summary>No transport security. For a local relay only, and startup logs a warning.</summary>
    None,

    /// <summary>Connects in the clear and upgrades with STARTTLS before authenticating.</summary>
    StartTls,

    /// <summary>TLS from the first byte, the usual choice for port 465.</summary>
    SslOnConnect,
}
