using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Configuration;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenApi;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Declares Toamaisutaa's security schemes on a generated OpenAPI document.
/// </summary>
/// <remarks>
/// The one public type in this package. A security scheme is a document-level declaration, so it
/// used to be thirty-five lines every application pasted into its own <c>Program.cs</c> - and a
/// pasted transformer drifts: one deployment hardcoded Keycloak's authorization URL into its copy
/// while running Pocket ID, so its Authorize button pointed at an issuer that was not there.
/// </remarks>
public static class ToamaisutaaOpenApiExtensions
{
    /// <summary>
    /// Adds an OpenAPI document carrying Toamaisutaa's security schemes.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">Configuration root or section parent holding <paramref name="sectionName"/>.</param>
    /// <param name="documentName">Document name, matching <c>AddOpenApi</c>'s own default.</param>
    /// <param name="configureOptions">Runs after the schemes are added, for an application that has
    /// transformers of its own. Calling <c>AddOpenApi</c> a second time for the same document would
    /// register everything twice.</param>
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

        // The same named client the discovery health check uses, because it is the same document
        // fetched from the same issuer: a proxy or a private certificate authority is configured
        // once and both reach it.
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
    /// <c>AddToamaisutaaBearer</c> and <c>AddToamaisutaaAuthorization</c> already bind. Where
    /// nothing has bound them there is no authority to describe, and the document gets the bearer
    /// scheme alone.
    /// </remarks>
    public static OpenApiOptions AddToamaisutaaSecuritySchemes(this OpenApiOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.AddDocumentTransformer((document, context, cancellationToken) =>
            ToamaisutaaSecuritySchemes.ApplyAsync(document, context.ApplicationServices, cancellationToken));

        options.AddOperationTransformer((operation, context, _) =>
        {
            // The document-level requirement would otherwise put a padlock on /auth/login too,
            // which is exactly backwards: it is the endpoint you call because you have no token
            // yet. An empty requirement list on an operation overrides the document's.
            if (context.Description.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any())
                operation.Security = [];

            return Task.CompletedTask;
        });

        return options;
    }
}
