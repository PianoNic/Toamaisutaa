using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Microsoft.AspNetCore.Authorization;

public static class ToamaisutaaFreshSecondFactorExtensions
{
    /// <summary>
    /// Requires a second factor presented within <paramref name="within"/>, rather than merely at
    /// some point in this session's history.
    /// </summary>
    /// <remarks>
    /// Reads <c>toa_2fa_at</c>, the last <i>live</i> factor, so a device-trusted sign-in fails this
    /// until the user steps up. Fails closed: a missing or unparseable claim is a refusal.
    /// </remarks>
    /// <param name="builder">The policy being built.</param>
    /// <param name="within">
    /// How recently the factor must have been presented, for example five minutes for a destructive action.
    /// </param>
    public static AuthorizationPolicyBuilder RequireFreshSecondFactor(
        this AuthorizationPolicyBuilder builder,
        TimeSpan within)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (within <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(within), within, "A freshness window has to be positive.");

        return builder.RequireAssertion(context =>
        {
            var services = (context.Resource as HttpContext)?.RequestServices;

            // Only this application's own tokens: toa_2fa_at is its claim, and on another issuer's token
            // it is whatever that issuer, or a user editing their profile there, put in it.
            var localIssuer = services?.GetService<IOptions<ToamaisutaaLocalLoginOptions>>()?.Value.Issuer;

            // The clock that stamped toa_2fa_at, so the two agree on what "now" is.
            var now = (services?.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow();

            var claim = context.User.FindAll(ToamaisutaaDefaults.SecondFactorAtClaim)
                .FirstOrDefault(found => localIssuer is not null && string.Equals(found.Issuer, localIssuer, StringComparison.Ordinal))
                ?.Value;

            if (!long.TryParse(claim, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds))
                return false;

            var presentedAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

            // A timestamp from the future is refused, so a skewed issuer cannot mint a long-lived "fresh" factor.
            return presentedAt <= now && now - presentedAt <= within;
        });
    }
}
