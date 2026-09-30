using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Configuration;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenApi;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Declares Toamaisutaa's security schemes on a generated OpenAPI document.
/// </summary>
public static class ToamaisutaaOpenApiExtensions
{
    /// <summary>
    /// Adds an OpenAPI document carrying Toamaisutaa's security schemes.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">Configuration root or section parent holding <paramref name="sectionName"/>.</param>
    /// <param name="documentName">Document name, matching <c>AddOpenApi</c>'s own default.</param>
    /// <param name="configureOptions">Runs after the schemes are added. Use it for your own transformers
    /// instead of calling <c>AddOpenApi</c> again, which would register everything twice.</param>
    /// <param name="sectionName">Configuration section the OIDC settings are read from.</param>
    public static IServiceCollection AddToamaisutaaOpenApi(
        this IServiceCollection services,
        IConfiguration configuration,
        string documentName = "v1",
        Action<OpenApiOptions>? configureOptions = null,
        string sectionName = ToamaisutaaDefaults.ConfigurationSection)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ToamaisutaaOidcOptions>().Bind(configuration.GetSection(sectionName));

        // Shares the discovery health check's named client, so a proxy or private CA is configured once.
        services.AddHttpClient(ToamaisutaaDefaults.DiscoveryHttpClientName);

        services.AddOpenApi(documentName, options =>
        {
            options.AddToamaisutaaSecuritySchemes();
            configureOptions?.Invoke(options);
        });

        return services;
    }

    /// <summary>
    /// Adds the schemes to a document an application configures itself, for the case where
    /// <c>AddOpenApi</c> is already called with options of its own.
    /// </summary>
    /// <remarks>
    /// Reads <see cref="ToamaisutaaOidcOptions"/> from the container, which
    /// <c>AddToamaisutaaBearer</c> and <c>AddToamaisutaaAuthorization</c> bind. Unbound, the document
    /// gets the bearer scheme alone.
    /// </remarks>
    public static OpenApiOptions AddToamaisutaaSecuritySchemes(this OpenApiOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // One per document, not per request, so readers of the anonymous document cannot set the rate of issuer fetches.
        var metadata = new AuthorizationServerMetadataCache();

        options.AddDocumentTransformer((document, context, cancellationToken) =>
            ToamaisutaaSecuritySchemes.ApplyAsync(document, metadata, context.ApplicationServices, cancellationToken));

        options.AddOperationTransformer((operation, context, _) =>
        {
            // An empty requirement list overrides the document's, so anonymous endpoints like /auth/login get no padlock.
            if (context.Description.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any())
                operation.Security = [];

            return Task.CompletedTask;
        });

        return options;
    }
}
