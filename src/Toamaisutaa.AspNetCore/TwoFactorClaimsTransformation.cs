using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Adds <c>amr</c> and <c>toa_2fa_required</c> to a token this package did not issue, so the same
/// policy covers identity-provider sign-ins.
/// </summary>
/// <remarks>
/// This is enforcement by the application, not by the package. Toamaisutaa never sees the exchange
/// where an identity provider decides what a user proved, so all this can do is read what the local
/// enrolment says and let a policy act on it. A user enrolled here who signs in there is described
/// as having presented a second factor because their provider, not this package, is what actually
/// asked for one.
/// </remarks>
internal sealed class TwoFactorClaimsTransformation(
    IServiceProvider services,
    IOptions<ToamaisutaaTwoFactorOptions> options,
    IOptions<ToamaisutaaProvisioningOptions> provisioningOptions) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Identity?.IsAuthenticated != true)
            return principal;

        // A locally issued token already carries amr from the issuer, and it is the authority on
        // what was actually presented. Nothing to add, and nothing worth a database read.
        if (principal.HasClaim(claim => claim.Type == ToamaisutaaDefaults.AuthenticationMethodClaim))
            return principal;

        var subject = principal.FindFirst(provisioningOptions.Value.ClaimNames.Subject)?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (subject is null)
            return principal;

        var logins = services.GetService(typeof(IExternalLoginStore)) as IExternalLoginStore;
        var enrolments = services.GetService(typeof(ITwoFactorStore)) as ITwoFactorStore;

        if (logins is null || enrolments is null)
            return principal;

        var login = await logins.FindAsync(ToamaisutaaDefaults.ProviderKey, subject);
        if (login is null)
            return principal;

        var enrolment = await enrolments.FindAsync(login.UserId);
        var enrolled = enrolment is { ConfirmedAt: not null };

        // Cloned rather than mutated: the principal handed in belongs to the authentication
        // handler, and a transformation that edits it in place is run again on every request in
        // some pipelines and accumulates duplicates.
        var clone = principal.Clone();
        var identity = clone.Identities.First();

        if (enrolled)
            identity.AddClaim(new Claim(ToamaisutaaDefaults.AuthenticationMethodClaim, ToamaisutaaDefaults.MultiFactorMethod));
        else if (options.Value.Enforcement == TwoFactorEnforcement.RequiredForAll)
            identity.AddClaim(new Claim(ToamaisutaaDefaults.TwoFactorRequiredClaim, "true"));

        return clone;
    }
}
