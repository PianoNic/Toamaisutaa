namespace Toamaisutaa.Abstractions;

/// <summary>Names Toamaisutaa uses when nothing else is configured.</summary>
public static class ToamaisutaaDefaults
{
    /// <summary>Identifies the provider on an external login row. Equals the bearer scheme name,
    /// so a single-provider deployment never has to think about it.</summary>
    public const string ProviderKey = "Bearer";

    /// <summary>Named <c>HttpClient</c> the userinfo enrichment resolves.</summary>
    public const string UserInfoHttpClientName = "toamaisutaa-userinfo";

    /// <summary>Where the SPA's runtime configuration is served from.</summary>
    public const string ConfigurationEndpointPattern = "/api/app";

    /// <summary>Configuration section every options type binds from.</summary>
    public const string ConfigurationSection = "Oidc";

    /// <summary>Configuration section local password login binds from.</summary>
    public const string LocalLoginConfigurationSection = "LocalLogin";

    /// <summary>Key id stamped on the local signing key, so the bearer layer can tell it apart from
    /// the identity provider's keys and refuse to validate one issuer's tokens with the other's
    /// key.</summary>
    public const string LocalSigningKeyId = "toamaisutaa-local";

    /// <summary>Configuration section two-factor authentication binds from.</summary>
    public const string TwoFactorConfigurationSection = "TwoFactor";

    /// <summary>
    /// RFC 8176 authentication method references. Standard, not invented, so a policy or a gateway
    /// that already understands <c>amr</c> keeps working against locally issued tokens.
    /// </summary>
    public const string AuthenticationMethodClaim = "amr";

    /// <summary>The value in <c>amr</c> that means a second factor was actually presented.</summary>
    public const string MultiFactorMethod = "mfa";

    /// <summary>Carries <see cref="ToamaisutaaUser.SecurityStamp"/> on a locally issued token.</summary>
    public const string SecurityStampClaim = "toa_stamp";

    /// <summary>
    /// Set on a token for a user who has not enrolled while enforcement demands it. Non-standard
    /// because nothing standard says it, and prefixed so it cannot collide with a provider's own.
    /// </summary>
    public const string TwoFactorRequiredClaim = "toa_2fa_required";

    /// <summary>Configuration section trusted devices bind from.</summary>
    public const string TrustedDevicesConfigurationSection = "TrustedDevices";

    /// <summary>How the second factor was satisfied: <c>otp</c>, <c>recovery</c> or <c>device</c>.</summary>
    public const string TwoFactorSourceClaim = "toa_2fa_source";

    /// <summary>
    /// Unix seconds of the last <i>live</i> second factor. A device-trusted token carries the
    /// original challenge time, so <c>now - toa_2fa_at</c> is how a step-up policy asks for
    /// freshness rather than merely asking whether the factor was cached.
    /// </summary>
    public const string SecondFactorAtClaim = "toa_2fa_at";

    /// <summary>
    /// The refresh family this token belongs to, which is what "session" means here: it survives
    /// rotation, so it names the same session for as long as the session lasts. Step-up needs it to
    /// find the row to elevate, and to elevate that one rather than every session the user has.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Namespaced rather than the registered <c>sid</c>, which an identity provider may already put
    /// on its own tokens - two issuers writing the same claim to mean two different sessions is a
    /// collision nothing downstream could untangle. Every non-standard claim here carries the
    /// <c>toa_</c> prefix for the same reason.
    /// </para>
    /// <para>
    /// <b>An identifier, not a credential.</b> Nothing authorises on it: it names a row, it does not
    /// prove anything about the caller, and the bearer token carrying it was already the thing that
    /// had to be protected. Exposing it to a client that already holds that token grants nothing it
    /// did not have.
    /// </para>
    /// </remarks>
    public const string SessionIdClaim = "toa_sid";
}
