namespace Toamaisutaa.Abstractions;

/// <summary>Names Toamaisutaa uses when nothing else is configured.</summary>
public static class ToamaisutaaDefaults
{
    /// <summary>Identifies the provider on an external login row. Equals the bearer scheme name,
    /// so a single-provider deployment never has to think about it.</summary>
    public const string ProviderKey = "Bearer";

    /// <summary>Named <c>HttpClient</c> the userinfo enrichment resolves.</summary>
    public const string UserInfoHttpClientName = "toamaisutaa-userinfo";

    /// <summary>Named <c>HttpClient</c> anything reaching the issuer's discovery document resolves:
    /// the health check, and the OpenAPI document's OAuth2 URLs.</summary>
    public const string DiscoveryHttpClientName = "toamaisutaa-discovery";

    /// <summary>Name the discovery health check is registered under, and the name a health report
    /// prints it as.</summary>
    public const string DiscoveryHealthCheckName = "toamaisutaa-oidc-discovery";

    /// <summary>
    /// The <c>System.Diagnostics.Metrics</c> meter every instrument in this package is published on.
    /// Subscribe with <c>AddMeter(ToamaisutaaDefaults.MeterName)</c>.
    /// </summary>
    public const string MeterName = "Toamaisutaa";

    /// <summary>Where the SPA's runtime configuration is served from.</summary>
    public const string ConfigurationEndpointPattern = "/api/app";

    /// <summary>Configuration section every options type binds from.</summary>
    public const string ConfigurationSection = "Oidc";

    /// <summary>Configuration section local password login binds from.</summary>
    public const string LocalLoginConfigurationSection = "LocalLogin";

    /// <summary>Key id stamped on the symmetric local signing key, so the bearer layer can tell it
    /// apart from the identity provider's keys and refuse to validate one issuer's tokens with the
    /// other's key. Reserved: an entry in <c>LocalLogin:SigningKeys</c> may not claim it.</summary>
    public const string LocalSigningKeyId = "toamaisutaa-local";

    /// <summary>Where the public halves of <c>LocalLogin:SigningKeys</c> are published, relative to
    /// <c>LocalLogin:EndpointPrefix</c>.</summary>
    public const string JwksEndpointPattern = "/.well-known/jwks.json";

    /// <summary>Configuration section two-factor authentication binds from.</summary>
    public const string TwoFactorConfigurationSection = "TwoFactor";

    /// <summary>RFC 8176 authentication method references.</summary>
    public const string AuthenticationMethodClaim = "amr";

    /// <summary>The value in <c>amr</c> that means a second factor was actually presented.</summary>
    public const string MultiFactorMethod = "mfa";

    /// <summary>
    /// The value in <c>amr</c> for a sign-in proved by an emailed link rather than a password.
    /// </summary>
    /// <remarks>
    /// Not in the RFC 8176 registry; spelled as identity providers offering emailed sign-in already
    /// spell it. A policy requiring a typed password should read <c>pwd</c>, which is absent here.
    /// </remarks>
    public const string MagicLinkMethod = "email";

    /// <summary>
    /// RFC 8176's "proof-of-possession of a hardware-secured key", written to <c>amr</c> for a passkey.
    /// </summary>
    public const string HardwareKeyMethod = "hwk";

    /// <summary>
    /// RFC 8176's user-presence test, written to <c>amr</c> for every passkey. Only
    /// <see cref="MultiFactorMethod"/> indicates the authenticator also verified the user.
    /// </summary>
    public const string UserPresenceMethod = "user";

    /// <summary>Carries <see cref="ToamaisutaaUser.SecurityStamp"/> on a locally issued token.</summary>
    public const string SecurityStampClaim = "toa_stamp";

    /// <summary>Set on a token for a user who has not enrolled while enforcement demands it.</summary>
    public const string TwoFactorRequiredClaim = "toa_2fa_required";

    /// <summary>
    /// Set by <c>AddToamaisutaaTwoFactorClaims</c> on an identity provider's token when the user has
    /// a confirmed local enrolment. It says nothing about what they presented at this sign-in, so the
    /// <c>Toamaisutaa.TwoFactor</c> policy does not accept it.
    /// </summary>
    public const string TwoFactorEnrolledClaim = "toa_2fa_enrolled";

    /// <summary>Configuration section trusted devices bind from.</summary>
    public const string TrustedDevicesConfigurationSection = "TrustedDevices";

    /// <summary>Configuration section passkeys bind from.</summary>
    public const string PasskeysConfigurationSection = "Passkeys";

    /// <summary>How the second factor was satisfied: <c>otp</c>, <c>recovery</c>, <c>device</c> or
    /// <c>passkey</c>.</summary>
    public const string TwoFactorSourceClaim = "toa_2fa_source";

    /// <summary>
    /// Unix seconds of the last <i>live</i> second factor; a device-trusted token carries the original
    /// challenge time. Step-up policies read freshness from this.
    /// </summary>
    public const string SecondFactorAtClaim = "toa_2fa_at";

    /// <summary>
    /// The refresh family this token belongs to, which is what "session" means here: it survives
    /// rotation. An identifier, not a credential.
    /// </summary>
    /// <remarks>
    /// Namespaced rather than the registered <c>sid</c>, which an identity provider may already put on
    /// its own tokens with a different meaning.
    /// </remarks>
    public const string SessionIdClaim = "toa_sid";
}
