using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Makes <see cref="TwoFactorEnforcement.RequiredForAll"/> mean something: a token marked
/// <c>toa_2fa_required</c> reaches only the endpoints that let its user enrol. Here, like
/// <see cref="AdminRoleResultHandler"/>, because an endpoint naming its own policy skips the fallback.
/// </summary>
/// <remarks>
/// Answered here rather than through <c>Forbid</c>, whose <c>OnForbidden</c> log explains every 403 as
/// a missing role.
/// </remarks>
internal sealed class TwoFactorEnrolmentResultHandler(
    IOptions<ToamaisutaaTwoFactorOptions> options,
    IAuthorizationMiddlewareResultHandler inner) : IAuthorizationMiddlewareResultHandler
{
    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        var endpoint = context.GetEndpoint();

        if (authorizeResult.Succeeded
            && options.Value.Enforcement == TwoFactorEnforcement.RequiredForAll
            && string.Equals(context.User.FindFirst(ToamaisutaaDefaults.TwoFactorRequiredClaim)?.Value, "true", StringComparison.Ordinal)
            && endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is null
            && endpoint?.Metadata.GetMetadata<AllowsPendingTwoFactorEnrolment>() is null)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;

            await context.Response.WriteAsJsonAsync(new ErrorResponse
            {
                Error = "two_factor_enrolment_required",
                ErrorDescription = "TwoFactor:Enforcement is RequiredForAll and this account has no second factor. Enrol at /auth/2fa/begin or register a passkey first.",
            });

            return;
        }

        await inner.HandleAsync(next, context, policy, authorizeResult);
    }
}

/// <summary>On the endpoints a user who still has to enrol needs to reach in order to do it.</summary>
internal sealed class AllowsPendingTwoFactorEnrolment
{
    internal static readonly AllowsPendingTwoFactorEnrolment Instance = new();
}
