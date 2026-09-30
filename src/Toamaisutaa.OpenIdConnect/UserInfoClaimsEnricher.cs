using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Pocket ID, Okta and Entra leave groups out of the access token, so without userinfo those
/// deployments could never satisfy a role requirement.
/// </summary>
/// <remarks>
/// <see cref="HybridCache"/> joins the concurrent requests a cold page load fires with one token into
/// one userinfo call.
/// </remarks>
internal sealed class UserInfoClaimsEnricher(
    IOptions<ToamaisutaaOidcOptions> options,
    IOptions<ToamaisutaaLocalLoginOptions> localLogin,
    IHttpClientFactory httpClientFactory,
    HybridCache cache,
    ILoggerFactory loggerFactory)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger("Toamaisutaa.Auth");

    public async Task EnrichAsync(TokenValidatedContext context)
    {
        var settings = options.Value;

        // Never send a locally signed token to the identity provider, which would hand it a local credential.
        // Read off the base type: under UseSecurityTokenValidators the token is a JwtSecurityToken.
        if (string.Equals(context.SecurityToken?.Issuer, localLogin.Value.Issuer, StringComparison.Ordinal))
            return;

        if (!UserInfoDecision.ShouldFetch(settings.FetchClaimsFromUserInfo, context.Principal, settings.RoleClaim))
            return;

        if (context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        var accessToken = ReadAccessToken(context);
        if (accessToken is null)
            return;

        try
        {
            var claims = await FetchAsync(context, accessToken, context.HttpContext.RequestAborted);

            foreach (var claim in claims)
            {
                if (!identity.HasClaim(claim.Type, claim.Value))
                    identity.AddClaim(new Claim(claim.Type, claim.Value));
            }
        }
        catch (UserInfoUnavailableException)
        {
            // Thrown rather than returned empty, because an empty set would be cached as "no groups".
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            // A userinfo endpoint that is down must not turn a valid login into a 500.
            _logger.LogWarning(exception, "Could not read userinfo; deciding on the token's own claims.");
        }
    }

    private async Task<UserInfoClaim[]> FetchAsync(
        TokenValidatedContext context,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var endpoint = await EndpointAsync(context, cancellationToken);
        if (endpoint is null)
        {
            _logger.LogWarning("The issuer publishes no userinfo endpoint, so roles must come from the token itself.");
            return [];
        }

        var settings = options.Value;
        var duration = settings.UserInfoCacheDuration;

        return await cache.GetOrCreateAsync(
            CacheKey(settings, context, accessToken),
            (Enricher: this, Endpoint: endpoint, AccessToken: accessToken),
            static (state, cancellation) => state.Enricher.ReadAsync(state.Endpoint, state.AccessToken, cancellation),
            new HybridCacheEntryOptions
            {
                Expiration = duration,
                LocalCacheExpiration = duration,
                Flags = settings.ShareUserInfoCacheAcrossInstances
                    ? HybridCacheEntryFlags.None
                    : HybridCacheEntryFlags.DisableDistributedCache,
            },
            cancellationToken: cancellationToken);
    }

    private async ValueTask<UserInfoClaim[]> ReadAsync(string endpoint, string accessToken, CancellationToken cancellationToken)
    {
        var http = httpClientFactory.CreateClient(ToamaisutaaDefaults.UserInfoHttpClientName);

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await http.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("userinfo answered {Status}; deciding on the token's own claims.", (int)response.StatusCode);
            throw new UserInfoUnavailableException();
        }

        var claims = ClaimsJsonFlattener.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        return [.. claims.Select(claim => new UserInfoClaim(claim.Type, claim.Value))];
    }

    /// <summary>
    /// Never keyed on a 32-bit hash code, which would let one caller's roles be served to another.
    /// </summary>
    private static string CacheKey(ToamaisutaaOidcOptions settings, TokenValidatedContext context, string accessToken)
    {
        var scope = ScopeDigest(settings);

        var subject = context.Principal?.FindFirst("sub")?.Value
            ?? context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (subject is not null)
            return $"toamaisutaa:userinfo:{context.Scheme.Name}:{scope}:sub:{subject}";

        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        return $"toamaisutaa:userinfo:{context.Scheme.Name}:{scope}:tok:{digest}";
    }

    /// <summary>
    /// Without the issuer and audiences in the key, two services sharing one distributed cache would
    /// serve each other's claims for the same subject.
    /// </summary>
    private static string ScopeDigest(ToamaisutaaOidcOptions settings)
    {
        var audiences = settings.ValidAudiences.Count > 0
            ? string.Join(',', settings.ValidAudiences.Order(StringComparer.Ordinal))
            : settings.ClientId;

        var identity = $"{settings.Authority}\n{audiences}";

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
    }

    private static async Task<string?> EndpointAsync(TokenValidatedContext context, CancellationToken cancellationToken)
    {
        if (context.Options.ConfigurationManager is null)
            return context.Options.Configuration?.UserInfoEndpoint;

        var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(cancellationToken);
        return configuration.UserInfoEndpoint;
    }

    /// <summary>Prefers the validated token over the header, so a query-string token works too.</summary>
    private static string? ReadAccessToken(TokenValidatedContext context)
    {
        if (context.SecurityToken is JsonWebToken jsonWebToken && !string.IsNullOrEmpty(jsonWebToken.EncodedToken))
            return jsonWebToken.EncodedToken;

        var header = context.HttpContext.Request.Headers.Authorization.ToString();

        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? header["Bearer ".Length..].Trim()
            : null;
    }

    private sealed class UserInfoUnavailableException : Exception;
}
