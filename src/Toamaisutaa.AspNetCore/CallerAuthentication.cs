using System.Globalization;
using System.Security.Claims;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

internal static class CallerAuthentication
{
    /// <summary>
    /// When the caller last actually authenticated: the later of a local second factor
    /// (<c>toa_2fa_at</c>) and an identity-provider sign-in (<c>auth_time</c>). Read off the caller's
    /// own token, never a body, which is the one place a caller could otherwise vouch for themselves.
    /// Neither moves on a refresh.
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
