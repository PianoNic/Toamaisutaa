using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Makes <c>RequireAdminRoleGlobally</c> hold on every endpoint that is not anonymous.
/// </summary>
/// <remarks>
/// The option puts the role in the fallback and the default policy, and neither is consulted for
/// an endpoint that names a policy or roles of its own - so a <c>RequireAuthorization("...")</c>
/// endpoint answered 200 to anyone that policy admitted, admin or not. Every authorized request
/// ends here whatever its policy was, which is why the role is checked here as well.
/// </remarks>
internal sealed class AdminRoleResultHandler(
    IOptions<ToamaisutaaAuthorizationOptions> options,
    IAuthorizationMiddlewareResultHandler inner) : IAuthorizationMiddlewareResultHandler
{
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        var settings = options.Value;

        if (authorizeResult.Succeeded
            && settings.RequireAuthenticatedUser
            && settings.RequireAdminRoleGlobally
            && settings.AdminRole is { Length: > 0 } adminRole
            && context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is null
            && !context.User.IsInRole(adminRole))
        {
            return inner.HandleAsync(next, context, policy, PolicyAuthorizationResult.Forbid());
        }

        return inner.HandleAsync(next, context, policy, authorizeResult);
    }
}
