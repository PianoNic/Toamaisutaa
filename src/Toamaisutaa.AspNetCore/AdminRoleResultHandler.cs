using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Enforces <c>RequireAdminRoleGlobally</c> here because the fallback and default policies are not
/// consulted for an endpoint that names a policy of its own, while every authorized request passes here.
/// </summary>
internal sealed class AdminRoleResultHandler(
    IOptions<ToamaisutaaAuthorizationOptions> options,
    IAuthorizationMiddlewareResultHandler inner) : IAuthorizationMiddlewareResultHandler
{
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        var settings = options.Value;

        if (authorizeResult.Succeeded
            && settings.RequireAdminRoleGlobally
            // Blank counts as none, as it does for the policies: a whitespace role forbade everyone.
            && settings.AdminRole is { } adminRole
            && !string.IsNullOrWhiteSpace(adminRole)
            && context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is null
            && !context.User.IsInRole(adminRole))
        {
            return inner.HandleAsync(next, context, policy, PolicyAuthorizationResult.Forbid());
        }

        return inner.HandleAsync(next, context, policy, authorizeResult);
    }
}
