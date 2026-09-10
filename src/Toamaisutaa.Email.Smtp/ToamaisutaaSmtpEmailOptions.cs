namespace Toamaisutaa.Email.Smtp;

/// <summary>
/// Everything read from the <c>Email:Smtp</c> configuration section. Binds an SMTP transport and the
/// links the emails it sends point at; nothing here is required unless
/// <c>AddToamaisutaaSmtpEmail</c> is actually called.
/// </summary>
public sealed class ToamaisutaaSmtpEmailOptions
{
    public string? Host { get; set; }

    public int Port { get; set; } = 587;

    public string? User { get; set; }

    public string? Password { get; set; }

    /// <summary>How the connection is secured. <see cref="SmtpSecurityMode.Auto"/> picks TLS for
    /// port 465 and STARTTLS for everything else, which is right for almost every provider.</summary>
    public SmtpSecurityMode Security { get; set; } = SmtpSecurityMode.Auto;

    /// <summary>
    /// Skips validating the server's TLS certificate. For a self-signed relay on a private network
    /// only - off by default, and startup logs a warning when it is on.
    /// </summary>
    public bool SkipCertificateVerification { get; set; }

    public string From { get; set; } = string.Empty;

    public string? FromDisplayName { get; set; }

    /// <summary>
    /// The reset link, with <c>{token}</c> replaced by the raw token. The default template is the
    /// only thing that reads this - a custom <see cref="IPasswordResetEmailTemplate"/> can ignore it
    /// entirely.
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
    /// Where someone signs in, put at the end of the admin-issued password email. Optional and
    /// checked nowhere: a credentials email is still useful without it, and the person reading one
    /// was usually told what they are signing in to by whoever provisioned the account.
    /// </summary>
    public string? SignInUrl { get; set; }

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>How <see cref="ToamaisutaaSmtpEmailOptions.Security"/> secures the connection.</summary>
public enum SmtpSecurityMode
{
    /// <summary>TLS on connect for port 465, STARTTLS otherwise - MailKit's own default behaviour.</summary>
    Auto,

    /// <summary>No transport security. For a local relay only.</summary>
    None,

    /// <summary>Connects in the clear and upgrades with STARTTLS before authenticating.</summary>
    StartTls,

    /// <summary>TLS from the first byte, the usual choice for port 465.</summary>
    SslOnConnect,
}
