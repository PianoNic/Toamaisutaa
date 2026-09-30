using System.Globalization;
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
            var claim = context.User.FindFirst(ToamaisutaaDefaults.SecondFactorAtClaim)?.Value;

            if (!long.TryParse(claim, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds))
                return false;

            var presentedAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

            // A timestamp from the future is refused, so a skewed issuer cannot mint a long-lived "fresh" factor.
            return presentedAt <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow - presentedAt <= within;
        });
    }
}
