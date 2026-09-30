using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

internal static class ToamaisutaaSecuritySchemes
{
    public const string BearerScheme = "Bearer";

    public const string OAuth2Scheme = "OAuth2";

    public static async Task ApplyAsync(
        OpenApiDocument document,
        AuthorizationServerMetadataCache metadata,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var settings = services.GetRequiredService<IOptions<ToamaisutaaOidcOptions>>().Value;

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes[BearerScheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Paste the access_token from /auth/login or /auth/2fa/verify.",
        };

        // Separate requirements are an OR; one requirement holding both schemes would be an AND.
        List<OpenApiSecurityRequirement> requirements =
        [
            new() { [new OpenApiSecuritySchemeReference(BearerScheme, document)] = [] },
        ];

        if (await metadata.GetAsync(settings, services, cancellationToken) is { } issuer)
        {
            var scopes = Scopes(settings.Scope);

            document.Components.SecuritySchemes[OAuth2Scheme] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Description = "Sign in with the identity provider. Authorization code, the same flow the SPA uses.",
                Flows = new OpenApiOAuthFlows
                {
                    AuthorizationCode = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = issuer.AuthorizationUrl,
                        TokenUrl = issuer.TokenUrl,
                        RefreshUrl = issuer.TokenUrl,
                        Scopes = scopes,
                    },
                },
            };

            requirements.Add(new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference(OAuth2Scheme, document)] = [.. scopes.Keys],
            });
        }

        document.Security = requirements;
    }

    /// <summary>
    /// From <c>Oidc:Scope</c>, the string the SPA is handed, so the Authorize button asks for exactly
    /// what the SPA does.
    /// </summary>
    private static Dictionary<string, string> Scopes(string? scope) =>
        (scope ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(name => name, _ => string.Empty, StringComparer.Ordinal);
}
