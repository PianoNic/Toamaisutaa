using System.Security.Claims;

namespace Toamaisutaa.Core;

/// <summary>Whether a userinfo round trip is worth making.</summary>
internal static class UserInfoDecision
{
    /// <summary>
    /// Only when the token did not already answer the question. An issuer that puts roles in the
    /// access token pays nothing for enrichment being available.
    /// </summary>
    internal static bool ShouldFetch(bool enabled, ClaimsPrincipal? principal, string roleClaim)
    {
        if (!enabled || principal is null || string.IsNullOrWhiteSpace(roleClaim))
            return false;

        return !principal.HasClaim(claim => string.Equals(claim.Type, roleClaim, StringComparison.Ordinal));
    }
}
