using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// The relying-party half of the authorization code flow, one discovery document per provider. Nothing
/// here decides who signs in; it only says what a provider vouched for.
/// </summary>
internal sealed class ExternalProviderClient(
    IHttpClientFactory httpClients,
    IOptions<ToamaisutaaExternalLoginOptions> options,
    ILogger<ExternalProviderClient> logger)
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _configurations = new(StringComparer.Ordinal);

    internal Task<OpenIdConnectConfiguration> GetConfigurationAsync(string providerKey, CancellationToken cancellationToken) =>
        Manager(providerKey).GetConfigurationAsync(cancellationToken);

    /// <summary>Null when the provider would not redeem the code; the log line says why.</summary>
    internal async Task<string?> RedeemAsync(
        string providerKey,
        string code,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken)
    {
        var provider = options.Value.Providers[providerKey];
        var configuration = await GetConfigurationAsync(providerKey, cancellationToken);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = provider.ClientId!,
            ["code_verifier"] = codeVerifier,
        };

        // client_secret_post, which every provider this is written for accepts alongside basic.
        if (!string.IsNullOrEmpty(provider.ClientSecret))
            form["client_secret"] = provider.ClientSecret;

        using var response = await httpClients.CreateClient(ToamaisutaaDefaults.ExternalLoginHttpClientName)
            .PostAsync(configuration.TokenEndpoint, new FormUrlEncodedContent(form), cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            // The provider's error code only: the body can echo what was sent, the secret included.
            var error = await ReadErrorAsync(response, cancellationToken);

            logger.LogWarning(
                "External sign-in through {ProviderKey} failed: the token endpoint answered {StatusCode} {Error}.",
                providerKey,
                (int)response.StatusCode,
                error ?? "with no error code");

            return null;
        }

        var tokens = await response.Content.ReadFromJsonAsync<TokenEndpointResponse>(cancellationToken);

        if (string.IsNullOrEmpty(tokens?.IdToken))
        {
            logger.LogWarning(
                "External sign-in through {ProviderKey} failed: the token endpoint returned no id_token. Check that "
                + "the provider's Scopes include openid.",
                providerKey);

            return null;
        }

        return tokens.IdToken;
    }

    /// <summary>
    /// The ID token's claims, or null when it was not issued by this provider, to this client, for this
    /// sign-in.
    /// </summary>
    internal async Task<ClaimsIdentity?> ValidateIdTokenAsync(
        string providerKey,
        string idToken,
        string nonce,
        CancellationToken cancellationToken)
    {
        var result = await ValidateAsync(providerKey, idToken, cancellationToken);

        // Once more on an unknown key, which is what a provider's key rotation looks like from here.
        if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            Manager(providerKey).RequestRefresh();
            result = await ValidateAsync(providerKey, idToken, cancellationToken);
        }

        if (!result.IsValid)
        {
            logger.LogWarning(
                "External sign-in through {ProviderKey} failed: the ID token did not validate ({Reason}).",
                providerKey,
                result.Exception?.GetType().Name ?? "no reason given");

            return null;
        }

        // Bound to the request that began this sign-in, so an ID token issued for another one is refused.
        if (!string.Equals(result.ClaimsIdentity.FindFirst("nonce")?.Value, nonce, StringComparison.Ordinal))
        {
            logger.LogWarning("External sign-in through {ProviderKey} failed: the ID token's nonce is not this sign-in's.", providerKey);
            return null;
        }

        return result.ClaimsIdentity;
    }

    private async Task<TokenValidationResult> ValidateAsync(string providerKey, string idToken, CancellationToken cancellationToken)
    {
        var configuration = await GetConfigurationAsync(providerKey, cancellationToken);
        var issuer = configuration.Issuer;

        return await new JsonWebTokenHandler().ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidAudience = options.Value.Providers[providerKey].ClientId,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),

            // Microsoft's multi-tenant endpoints publish a template rather than an issuer, and each token
            // names its tenant. Anything else is compared exactly.
            IssuerValidator = (tokenIssuer, token, _) =>
            {
                var expected = issuer.Contains("{tenantid}", StringComparison.Ordinal)
                    && token is JsonWebToken jwt
                    && jwt.TryGetPayloadValue<string>("tid", out var tenant)
                        ? issuer.Replace("{tenantid}", tenant, StringComparison.Ordinal)
                        : issuer;

                return string.Equals(tokenIssuer, expected, StringComparison.Ordinal)
                    ? tokenIssuer
                    : throw new SecurityTokenInvalidIssuerException($"Issuer '{tokenIssuer}' is not '{expected}'.");
            },
        });
    }

    private ConfigurationManager<OpenIdConnectConfiguration> Manager(string providerKey) =>
        _configurations.GetOrAdd(providerKey, key =>
        {
            var authority = options.Value.Providers[key].Authority!.TrimEnd('/');

            return new ConfigurationManager<OpenIdConnectConfiguration>(
                authority + "/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),

                // The startup check has already refused plain http outside Development.
                new HttpDocumentRetriever(httpClients.CreateClient(ToamaisutaaDefaults.ExternalLoginHttpClientName)) { RequireHttps = false });
        });

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            return (await response.Content.ReadFromJsonAsync<TokenEndpointResponse>(cancellationToken))?.Error;
        }
        catch (Exception exception) when (exception is System.Text.Json.JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private sealed record TokenEndpointResponse
    {
        [JsonPropertyName("id_token")]
        public string? IdToken { get; init; }

        [JsonPropertyName("error")]
        public string? Error { get; init; }
    }
}
