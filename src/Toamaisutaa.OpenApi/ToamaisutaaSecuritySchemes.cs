using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

/// <summary>
/// What the document transformer writes: a bearer scheme, an OAuth2 scheme when the issuer's
/// discovery document can be read, and a document-wide requirement naming both.
/// </summary>
internal static class ToamaisutaaSecuritySchemes
{
    public const string BearerScheme = "Bearer";

    public const string OAuth2Scheme = "OAuth2";

    public static async Task ApplyAsync(
        OpenApiDocument document,
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

        // A list of requirements is an OR and a single requirement holding two schemes is an AND. It
        // has to be the first: one token gets you in, and which issuer minted it is precisely what
        // this API does not care about.
        List<OpenApiSecurityRequirement> requirements =
        [
            new() { [new OpenApiSecuritySchemeReference(BearerScheme, document)] = [] },
        ];

        if (await AuthorizationServerMetadata.DiscoverAsync(settings, services, cancellationToken) is { } issuer)
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
    /// The scopes the application itself requests, split out of <c>Oidc:Scope</c> - the same string
    /// the configuration endpoint hands the SPA, so the Authorize button asks for exactly what the
    /// SPA asks for and a token obtained here behaves like one obtained there.
    /// </summary>
    /// <remarks>
    /// No descriptions. Only the issuer knows what its scopes mean, and inventing a sentence per
    /// scope would put text in the document that nobody wrote.
    /// </remarks>
    private static Dictionary<string, string> Scopes(string? scope) =>
        (scope ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(name => name, _ => string.Empty, StringComparer.Ordinal);
}
