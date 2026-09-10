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
    /// the health check, and the OpenAPI document's OAuth2 URLs. Separate from the userinfo one so a
    /// handler or a proxy can be put on those without touching the path a signed-in request
    /// takes.</summary>
    public const string DiscoveryHttpClientName = "toamaisutaa-discovery";

    /// <summary>Name the discovery health check is registered under, and the name a health report
    /// prints it as.</summary>
    public const string DiscoveryHealthCheckName = "toamaisutaa-oidc-discovery";

    /// <summary>
    /// The <c>System.Diagnostics.Metrics</c> meter every instrument in this package is published on.
    /// Public because a metrics pipeline is subscribed by name and nothing else -
    /// <c>AddMeter(ToamaisutaaDefaults.MeterName)</c> - and a typo in a string literal produces no
    /// error, just a dashboard that stays empty.
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

    /// <summary>
    /// RFC 8176 authentication method references. Standard, not invented, so a policy or a gateway
    /// that already understands <c>amr</c> keeps working against locally issued tokens.
    /// </summary>
    public const string AuthenticationMethodClaim = "amr";

    /// <summary>The value in <c>amr</c> that means a second factor was actually presented.</summary>
    public const string MultiFactorMethod = "mfa";

    /// <summary>
    /// The value in <c>amr</c> for a sign-in proved by an emailed link rather than a password.
    /// </summary>
    /// <remarks>
    /// The one <c>amr</c> value here that the RFC 8176 registry does not define - it has nothing for
    /// possession of a mailbox - and it is spelled the way identity providers offering emailed
    /// sign-in already spell it, so a policy reading <c>amr</c> sees one value rather than two.
    /// Unprefixed for that reason, unlike the <c>toa_</c> claims: this is a value inside a standard
    /// claim, not a claim of ours. A policy that means "a password was typed" should read
    /// <c>pwd</c> and will not find it here, which is the point.
    /// </remarks>
    public const string MagicLinkMethod = "email";

    /// <summary>
    /// RFC 8176's "proof-of-possession of a hardware-secured key", written to <c>amr</c> for a
    /// passkey. It is the possession half of what a WebAuthn assertion proves.
    /// </summary>
    public const string HardwareKeyMethod = "hwk";

    /// <summary>
    /// RFC 8176's user-presence test, written to <c>amr</c> for a passkey. Every WebAuthn assertion
    /// requires it, so it is on every one of them; <see cref="MultiFactorMethod"/> is what
    /// distinguishes an assertion the authenticator also verified the user for - a PIN or a
    /// fingerprint - from one that only proved somebody touched the key.
    /// </summary>
    public const string UserPresenceMethod = "user";

    /// <summary>Carries <see cref="ToamaisutaaUser.SecurityStamp"/> on a locally issued token.</summary>
    public const string SecurityStampClaim = "toa_stamp";

    /// <summary>
    /// Set on a token for a user who has not enrolled while enforcement demands it. Non-standard
    /// because nothing standard says it, and prefixed so it cannot collide with a provider's own.
    /// </summary>
    public const string TwoFactorRequiredClaim = "toa_2fa_required";

    /// <summary>Configuration section trusted devices bind from.</summary>
    public const string TrustedDevicesConfigurationSection = "TrustedDevices";

    /// <summary>Configuration section passkeys bind from.</summary>
    public const string PasskeysConfigurationSection = "Passkeys";

    /// <summary>How the second factor was satisfied: <c>otp</c>, <c>recovery</c>, <c>device</c> or
    /// <c>passkey</c>.</summary>
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
