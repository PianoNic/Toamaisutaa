using System.Security.Claims;

namespace Toamaisutaa.Core;

internal static class UserInfoDecision
{
    internal static bool ShouldFetch(bool enabled, ClaimsPrincipal? principal, string roleClaim)
    {
        if (!enabled || principal is null || string.IsNullOrWhiteSpace(roleClaim))
            return false;

        return !principal.HasClaim(claim => string.Equals(claim.Type, roleClaim, StringComparison.Ordinal));
    }
}
