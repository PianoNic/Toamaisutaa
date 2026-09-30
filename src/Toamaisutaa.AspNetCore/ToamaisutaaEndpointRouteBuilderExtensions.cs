using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Toamaisutaa.Abstractions;
using Toamaisutaa.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

public static class ToamaisutaaEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Serves the SPA's OIDC configuration at runtime, anonymously, since it is needed before sign-in.
    /// To add fields of your own, inject <see cref="IToamaisutaaClientConfigurationProvider"/> into
    /// your own endpoint instead.
    /// </summary>
    /// <param name="endpoints">The builder to map into. A <c>RouteGroupBuilder</c> is one.</param>
    /// <param name="pattern">Where to serve it.</param>
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
            // No-store is set by the provider, so it also holds for consumers' own endpoints.
            .MapGet(pattern, (HttpContext context, IToamaisutaaClientConfigurationProvider provider) =>
                Results.Ok(provider.GetConfiguration(context)))
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
