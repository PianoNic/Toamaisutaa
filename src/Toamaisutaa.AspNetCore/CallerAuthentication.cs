using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
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

    /// <summary>
    /// <see cref="AuthenticatedAt"/>, or for an account with no password the start of the live session the token
    /// names in <c>toa_sid</c> when that is later.
    /// </summary>
    /// <remarks>
    /// A local token after an identity-provider sign-in carries neither claim, so without the session's start a
    /// passwordless account could never prove a fresh sign-in. A refresh rotates the token inside the same family and
    /// leaves <see cref="ToamaisutaaRefreshToken.FamilyStartedAt"/> alone, so it never counts as signing in again. This is
    /// the source linking a provider already reads. An account with a password keeps proving it with the password: a
    /// session that started a minute ago is still only a bearer token to whoever holds it.
    /// </remarks>
    internal static async Task<DateTimeOffset?> SignedInAtAsync(HttpContext context, Guid userId, CancellationToken cancellationToken)
    {
        var claimed = AuthenticatedAt(context.User);

        if (context.RequestServices.GetService<IPasswordCredentialStore>() is { } credentials
            && await credentials.FindByUserIdAsync(userId, cancellationToken) is not null)
        {
            return claimed;
        }

        if (!Guid.TryParse(context.User.FindFirst(ToamaisutaaDefaults.SessionIdClaim)?.Value, out var family)
            || context.RequestServices.GetService<IRefreshTokenStore>() is not { } refreshTokens
            || await refreshTokens.FindLiveByFamilyAsync(family, cancellationToken) is not { } live
            || live.UserId != userId)
        {
            return claimed;
        }

        return claimed is { } at && at > live.FamilyStartedAt ? at : live.FamilyStartedAt;
    }
}
