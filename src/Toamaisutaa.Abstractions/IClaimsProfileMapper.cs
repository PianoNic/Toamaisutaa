using System.Security.Claims;

namespace Toamaisutaa.Abstractions;

/// <summary>
/// Turns a validated principal into the profile provisioning stores. The documented extension
/// point: register your own before <c>AddToamaisutaaProvisioning</c> to map claims your way.
/// </summary>
public interface IClaimsProfileMapper
{
    /// <summary>Throws when the principal carries no subject claim, because a profile without a
    /// subject cannot be linked to anything.</summary>
    ExternalUserProfile Map(ClaimsPrincipal principal);
}
