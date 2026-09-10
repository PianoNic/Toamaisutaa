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
/// Claims the access token does not carry, fetched from the endpoint OIDC puts them on.
/// Pocket ID publishes group membership in the ID token and userinfo while keeping the access token
/// minimal; Okta and Entra leave groups out to bound token size. This layer validates the access
/// token, so without this those deployments could never satisfy a role requirement.
/// </summary>
/// <remarks>
/// Cached through <see cref="HybridCache"/>. The reason is the cold start: a browser reload fires a
/// dozen requests carrying the same token at once, and a plain memory cache is empty for all of
/// them, so the issuer takes a dozen userinfo calls to answer one page. HybridCache runs the first
/// and joins the rest to it. The second level is left switched off unless
/// <see cref="ToamaisutaaOidcOptions.ShareUserInfoCacheAcrossInstances"/> asks for it: these entries
/// decide authorization, and a registered <c>IDistributedCache</c> is not on its own a statement
/// that they belong in it.
/// </remarks>
internal sealed class UserInfoClaimsEnricher(
    IOptions<ToamaisutaaOidcOptions> options,
    IHttpClientFactory httpClientFactory,
    HybridCache cache,
    ILoggerFactory loggerFactory)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger("Toamaisutaa.Auth");

    public async Task EnrichAsync(TokenValidatedContext context)
    {
        var settings = options.Value;

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
            // Already logged with its status where it happened. It leaves the cache factory as an
            // exception rather than as an empty claim set because an empty claim set would be
            // stored, and one 503 would then read as "this user has no groups" until it expired.
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            // A userinfo endpoint that is down must not turn a valid login into a 500. The claims
            // already on the token still decide.
            _logger.LogWarning(exception, "Could not read userinfo; deciding on the token's own claims.");
        }
    }

    /// <summary>
    /// The endpoint is resolved outside the cache: an issuer that publishes none is a permanent
    /// answer that no expiry should be attached to, and the configuration manager caches it anyway.
    /// </summary>
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
    /// Keyed on the subject, not on the token: the same person's claims are the same claims across
    /// their tokens, and a key derived from a 32-bit hash code would let one caller's roles be
    /// served to another. Falls back to a SHA-256 of the token when the principal somehow has no
    /// subject, which is still collision-free.
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
    /// Which deployment the entry belongs to: the issuer it was read from, and the audiences this
    /// service accepts. The scheme name is "Bearer" for every consumer of the package, so without
    /// this the key is the subject alone - and two services against one issuer, holding different
    /// scopes and sharing one distributed cache, would serve each other's claims for that subject.
    /// Hashed rather than spelled out because an authority is a URL and a cache key is not.
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

    /// <summary>The token exactly as presented. Taken from the validated token rather than the
    /// Authorization header, so a token that arrived on the query string works too.</summary>
    private static string? ReadAccessToken(TokenValidatedContext context)
    {
        if (context.SecurityToken is JsonWebToken jsonWebToken && !string.IsNullOrEmpty(jsonWebToken.EncodedToken))
            return jsonWebToken.EncodedToken;

        var header = context.HttpContext.Request.Headers.Authorization.ToString();

        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? header["Bearer ".Length..].Trim()
            : null;
    }

    /// <summary>Carries nothing and is never seen outside this class - it exists only to leave the
    /// cache factory without a value to store.</summary>
    private sealed class UserInfoUnavailableException : Exception;
}
