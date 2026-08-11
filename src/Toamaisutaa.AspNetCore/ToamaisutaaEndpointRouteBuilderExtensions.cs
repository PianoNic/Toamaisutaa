using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Serves the SPA's OIDC configuration at runtime, so the frontend build carries no
    /// environment. Anonymous, because the fallback policy would otherwise make it unreachable
    /// before sign-in - which is exactly when it is needed.
    /// </summary>
    /// <remarks>
    /// Applications that serve their own fields from the same route should inject
    /// <see cref="IToamaisutaaClientConfigurationProvider"/> into their own endpoint instead of
    /// calling this.
    /// </remarks>
    public static IEndpointConventionBuilder MapToamaisutaaConfiguration(
        this IEndpointRouteBuilder endpoints,
        string pattern = ToamaisutaaDefaults.ConfigurationEndpointPattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints
            .MapGet(pattern, (HttpContext context, IToamaisutaaClientConfigurationProvider provider)
                => Results.Ok(provider.GetConfiguration(context)))
            .AllowAnonymous()
            .WithName("ToamaisutaaClientConfiguration");
    }
}
