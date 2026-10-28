namespace Toamaisutaa.Abstractions;

/// <summary>
/// One (provider, subject) pair pointing at a local user. The pair is unique; the issuer is stored
/// but not part of the key.
/// </summary>
public class ToamaisutaaExternalLogin
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    /// <summary>The authentication scheme name, which is what consumers configure and read.</summary>
    public string ProviderKey { get; set; } = default!;

    /// <summary>The <c>sub</c> claim: the stable external identity.</summary>
    public string Subject { get; set; } = default!;

    /// <summary>The <c>iss</c> claim as seen at sign-in. Informational today.</summary>
    public string? Issuer { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? LastSignInAt { get; set; }

    /// <summary>The address the provider gave at the last sign-in through it, as it gave it.</summary>
    public string? Email { get; set; }

    /// <summary>
    /// Whether the provider said it verified <see cref="Email"/>. Recorded whatever the configuration;
    /// whether to believe it is decided when a token is issued, by that provider's
    /// <c>TrustEmailVerified</c>.
    /// </summary>
    public bool EmailVerified { get; set; }
}
