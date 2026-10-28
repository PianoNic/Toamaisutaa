using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore;

/// <summary>The caller's own <c>sub</c>, so an event an administrator caused says who caused it.</summary>
internal sealed class HttpContextAuthenticationActor(IHttpContextAccessor accessor) : IAuthenticationActor
{
    public string? Subject =>
        accessor.HttpContext?.User is { Identity.IsAuthenticated: true } user
            ? user.FindFirst("sub")?.Value
            : null;

    internal static void Register(IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.TryAddSingleton<IAuthenticationActor, HttpContextAuthenticationActor>();
    }
}
