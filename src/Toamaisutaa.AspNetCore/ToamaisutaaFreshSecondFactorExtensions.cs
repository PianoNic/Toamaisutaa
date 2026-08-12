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
    /// <para>
    /// Reads <c>toa_2fa_at</c>, which carries the last <i>live</i> factor - so a device-trusted
    /// sign-in reports the original challenge rather than now, and fails this until the user steps
    /// up. That is the distinction the claim exists for: "not cached" is cruder and wrong, because a
    /// live code entered twenty minutes ago is not fresh either.
    /// </para>
    /// <para>
    /// An extension on the builder rather than a policy factory, so it composes:
    /// <c>RequireAuthenticatedUser().RequireFreshSecondFactor(...).RequireRole(...)</c> all in one
    /// policy. It adds a requirement; it does not own the policy.
    /// </para>
    /// <para>
    /// Fails closed. A missing or unparseable claim is a refusal, not a pass - the whole point is to
    /// be certain, and "the claim was not there" is not evidence that anything happened.
    /// </para>
    /// </remarks>
    /// <param name="builder">The policy being built.</param>
    /// <param name="within">
    /// How recently the factor must have been presented. Five minutes is a common choice for a
    /// destructive action; there is no default, because the right window is the application's call.
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

            // A token from the future is a clock problem, not a fresh factor. Refusing keeps a
            // skewed issuer from being a way past this rather than into it.
            return presentedAt <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow - presentedAt <= within;
        });
    }
}
