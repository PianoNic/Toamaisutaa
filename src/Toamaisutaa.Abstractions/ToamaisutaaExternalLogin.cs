namespace Toamaisutaa.Abstractions;

/// <summary>
/// One (provider, subject) pair pointing at a local user. The pair is unique; the issuer is stored
/// alongside it but is not part of the key, so a later move to issuer-based identity has the data
/// it needs without a backfill.
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
}
