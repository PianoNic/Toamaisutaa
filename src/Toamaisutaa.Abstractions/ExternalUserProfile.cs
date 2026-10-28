namespace Toamaisutaa.Abstractions;

/// <summary>
/// The identity as the provider describes it, with nothing local attached. Produced by
/// <see cref="IClaimsProfileMapper"/> and consumed by provisioning.
/// </summary>
public sealed record ExternalUserProfile
{
    /// <summary>The <c>sub</c> claim.</summary>
    public required string Subject { get; init; }

    public string? Issuer { get; init; }

    public string? UserName { get; init; }

    public string? Email { get; init; }

    /// <summary>
    /// The provider's <c>email_verified</c>, or null when it sent none. Nothing here uses it; a custom
    /// policy that links accounts by email should require it true, or it links whoever typed the address.
    /// </summary>
    public bool? EmailVerified { get; init; }

    /// <summary>Already resolved through the fallback chain, so consumers never repeat it.</summary>
    public string? DisplayName { get; init; }

    public string? PictureUrl { get; init; }
}
