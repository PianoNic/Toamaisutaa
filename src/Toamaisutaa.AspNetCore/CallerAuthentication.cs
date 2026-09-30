using System.Globalization;
using System.Security.Claims;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

internal static class CallerAuthentication
{
    /// <summary>
    /// Read off the caller's own token, never a body, so a caller cannot vouch for their own freshness.
    /// </summary>
    internal static DateTimeOffset? AuthenticatedAt(ClaimsPrincipal principal)
    {
        DateTimeOffset? latest = null;

        foreach (var type in new[] { ToamaisutaaDefaults.SecondFactorAtClaim, "auth_time" })
        {
            if (long.TryParse(principal.FindFirst(type)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds))
            {
                var at = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
                if (latest is null || at > latest)
                    latest = at;
            }
        }

        return latest;
    }
}
