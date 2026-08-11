using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
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
internal sealed class UserInfoClaimsEnricher(
    IOptions<ToamaisutaaOidcOptions> options,
    IHttpClientFactory httpClientFactory,
    IMemoryCache cache,
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

            foreach (var (type, value) in claims)
            {
                if (!identity.HasClaim(type, value))
                    identity.AddClaim(new Claim(type, value));
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            // A userinfo endpoint that is down must not turn a valid login into a 500. The claims
            // already on the token still decide.
            _logger.LogWarning(exception, "Could not read userinfo; deciding on the token's own claims.");
        }
    }

    private async Task<IReadOnlyList<(string Type, string Value)>> FetchAsync(
        TokenValidatedContext context,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var key = CacheKey(context, accessToken);

        if (cache.TryGetValue<IReadOnlyList<(string, string)>>(key, out var cached) && cached is not null)
            return cached;

        var endpoint = await EndpointAsync(context, cancellationToken);
        if (endpoint is null)
        {
            _logger.LogWarning("The issuer publishes no userinfo endpoint, so roles must come from the token itself.");
            return [];
        }

        var http = httpClientFactory.CreateClient(ToamaisutaaDefaults.UserInfoHttpClientName);

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await http.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("userinfo answered {Status}; deciding on the token's own claims.", (int)response.StatusCode);
            return [];
        }

        var claims = ClaimsJsonFlattener.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        cache.Set(key, claims, options.Value.UserInfoCacheDuration);
        return claims;
    }

    /// <summary>
    /// Keyed on the subject, not on the token: the same person's claims are the same claims across
    /// their tokens, and a key derived from a 32-bit hash code would let one caller's roles be
    /// served to another. Falls back to a SHA-256 of the token when the principal somehow has no
    /// subject, which is still collision-free.
    /// </summary>
    private static string CacheKey(TokenValidatedContext context, string accessToken)
    {
        var subject = context.Principal?.FindFirst("sub")?.Value
            ?? context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (subject is not null)
            return $"toamaisutaa:userinfo:{context.Scheme.Name}:sub:{subject}";

        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken)));
        return $"toamaisutaa:userinfo:{context.Scheme.Name}:tok:{digest}";
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
}
