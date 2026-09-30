using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Never writes <c>amr=mfa</c>: being enrolled is not presenting a second factor, and claiming it would
/// let a phished provider password satisfy the second-factor policy.
/// </summary>
internal sealed class TwoFactorClaimsTransformation(
    IServiceProvider services,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    IOptions<ToamaisutaaProvisioningOptions> provisioningOptions,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Identity?.IsAuthenticated != true)
            return principal;

        // Recognised by issuer, not by the presence of amr, which most identity providers also send.
        if (principal.FindFirst("iss")?.Value is { } issuer
            && string.Equals(issuer, localLogin.Value.Issuer, StringComparison.Ordinal))
        {
            return principal;
        }

        var subject = principal.FindFirst(provisioningOptions.Value.ClaimNames.Subject)?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (subject is null)
            return principal;

        var logins = services.GetService(typeof(IExternalLoginStore)) as IExternalLoginStore;
        var enrolments = services.GetService(typeof(ITwoFactorStore)) as ITwoFactorStore;

        if (logins is null || enrolments is null)
            return principal;

        // The configured key, not the default constant, since provisioning wrote the login under it.
        var login = await logins.FindAsync(provisioningOptions.Value.ProviderKey, subject);
        if (login is null)
            return principal;

        var enrolment = await enrolments.FindAsync(login.UserId);
        var enrolled = enrolment is { ConfirmedAt: not null };

        // Cloned because a transformation can run more than once, and mutating in place accumulates duplicates.
        var clone = principal.Clone();
        var identity = clone.Identities.First();

        if (enrolled)
            identity.AddClaim(new Claim(ToamaisutaaDefaults.TwoFactorEnrolledClaim, "true"));
        else if (options.Value.Enforcement == TwoFactorEnforcement.RequiredForAll)
            identity.AddClaim(new Claim(ToamaisutaaDefaults.TwoFactorRequiredClaim, "true"));

        return clone;
    }
}
