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
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="pattern">
    /// Where to serve it. This is an application configuration endpoint rather than an auth one, so
    /// it is the most likely of these to collide with a consumer's own route conventions.
    /// </param>
    /// <param name="endpointNamePrefix">
    /// Prepended to the endpoint name, so this can be mapped into more than one group. Endpoint
    /// names are unique per application.
    /// </param>
    public static IEndpointConventionBuilder MapToamaisutaaConfiguration(
        this IEndpointRouteBuilder endpoints,
        string pattern = ToamaisutaaDefaults.ConfigurationEndpointPattern,
        string? endpointNamePrefix = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints
            .MapGet(pattern, (HttpContext context, IToamaisutaaClientConfigurationProvider provider)
                => Results.Ok(provider.GetConfiguration(context)))
            .AllowAnonymous()
            .WithName($"{endpointNamePrefix}ToamaisutaaClientConfiguration")
            .WithTags("Application configuration")
            .WithSummary("What the SPA reads at startup to configure its OIDC client.")
            .WithDescription(
                "Anonymous, because it is needed before anyone has signed in. To serve your own "
                + "fields alongside these, or from a different route, inject "
                + "`IToamaisutaaClientConfigurationProvider` into an endpoint of your own instead "
                + "of calling this.")
            .Produces<ToamaisutaaClientConfiguration>();
    }
}
