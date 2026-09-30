using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

/// <summary>
/// Endpoints are read from discovery, never derived: Keycloak's paths are wrong for every other
/// issuer, and a wrong one fails silently as a dead Authorize button.
/// </summary>
internal static class AuthorizationServerMetadata
{
    /// <summary>An unreachable issuer must not hang the document.</summary>
    private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

    public static async Task<(Uri AuthorizationUrl, Uri TokenUrl)?> DiscoverAsync(
        ToamaisutaaOidcOptions settings,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        if (MetadataAddress(settings) is not { } address)
            return null;

        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Toamaisutaa.OpenApi");

        // Mirrors the bearer handler: metadata over plaintext is refused unless configured otherwise.
        if (settings.RequireHttpsMetadata && address.Scheme != Uri.UriSchemeHttps)
        {
            logger.LogWarning(
                "The OpenAPI document has no OAuth2 scheme: {Address} is not https and Oidc:RequireHttpsMetadata "
                + "is on. The Bearer scheme is unaffected.",
                address);

            return null;
        }

        if (services.GetService<IHttpClientFactory>() is not { } clientFactory)
        {
            logger.LogWarning(
                "The OpenAPI document has no OAuth2 scheme: no IHttpClientFactory is registered, so {Address} "
                + "cannot be read. Call AddToamaisutaaOpenApi or AddHttpClient. The Bearer scheme is unaffected.",
                address);

            return null;
        }

        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        attempt.CancelAfter(DiscoveryTimeout);

        try
        {
            var client = clientFactory.CreateClient(ToamaisutaaDefaults.DiscoveryHttpClientName);

            using var response = await client.GetAsync(address, attempt.Token);
            response.EnsureSuccessStatusCode();

            using var metadata = JsonDocument.Parse(await response.Content.ReadAsStringAsync(attempt.Token));

            if (Endpoint(metadata, "authorization_endpoint") is not { } authorization
                || Endpoint(metadata, "token_endpoint") is not { } token)
            {
                logger.LogWarning(
                    "The OpenAPI document has no OAuth2 scheme: {Address} answered without an absolute "
                    + "authorization_endpoint and token_endpoint. The Bearer scheme is unaffected.",
                    address);

                return null;
            }

            return (PublicFacing(authorization, settings, logger), PublicFacing(token, settings, logger));
        }
        catch (Exception exception) when (
            exception is HttpRequestException or OperationCanceledException or JsonException
            && !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(
                "The OpenAPI document has no OAuth2 scheme: {Address} could not be read ({Reason}). "
                + "The Bearer scheme is unaffected, so tokens can still be pasted in.",
                address,
                exception.Message);

            return null;
        }
    }

    /// <summary>
    /// Moves an endpoint under <c>Oidc:InternalAuthority</c> back onto <c>Oidc:Authority</c>, because
    /// an issuer that builds URLs from the Host header (Keycloak without <c>KC_HOSTNAME</c>) answers
    /// the internal hop with a host no browser can resolve.
    /// </summary>
    /// <remarks>
    /// An endpoint on any other host is left alone: a separate login domain is ordinary.
    /// </remarks>
    private static Uri PublicFacing(Uri endpoint, ToamaisutaaOidcOptions settings, ILogger logger)
    {
        if (NullIfBlank(settings.InternalAuthority) is not { } internalAuthority
            || NullIfBlank(settings.Authority) is not { } publicAuthority
            || !Uri.TryCreate(internalAuthority, UriKind.Absolute, out var internalBase)
            || !Uri.TryCreate(publicAuthority, UriKind.Absolute, out var publicBase)
            || Rebase(endpoint, internalBase, publicBase) is not { } rebased
            || rebased == endpoint)
        {
            return endpoint;
        }

        logger.LogDebug(
            "The OpenAPI document carries {Rebased}: {Address} answered with {Discovered}, which is the address "
            + "this process reaches the issuer at rather than one a browser can.",
            rebased,
            internalBase,
            endpoint);

        return rebased;
    }

    private static Uri? Rebase(Uri endpoint, Uri internalBase, Uri publicBase)
    {
        if (!string.Equals(
            endpoint.GetLeftPart(UriPartial.Authority),
            internalBase.GetLeftPart(UriPartial.Authority),
            StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var basePath = internalBase.AbsolutePath.TrimEnd('/');

        // A shared host is not enough: outside the internal authority's path (another realm) is not ours to move.
        if (basePath.Length > 0
            && endpoint.AbsolutePath != basePath
            && !endpoint.AbsolutePath.StartsWith($"{basePath}/", StringComparison.Ordinal))
        {
            return null;
        }

        var address = publicBase.GetLeftPart(UriPartial.Authority)
            + publicBase.AbsolutePath.TrimEnd('/')
            + endpoint.AbsolutePath[basePath.Length..]
            + endpoint.Query
            + endpoint.Fragment;

        return Uri.TryCreate(address, UriKind.Absolute, out var rebased) ? rebased : null;
    }

    /// <summary>
    /// Duplicates <c>DiscoveryAddress</c> in <c>Toamaisutaa.OpenIdConnect</c> rather than referencing
    /// it, which would pull JwtBearer into a documentation package.
    /// </summary>
    private static Uri? MetadataAddress(ToamaisutaaOidcOptions settings)
    {
        var authority = NullIfBlank(settings.InternalAuthority) ?? NullIfBlank(settings.Authority);

        return authority is not null
            && Uri.TryCreate($"{authority.TrimEnd('/')}/.well-known/openid-configuration", UriKind.Absolute, out var address)
                ? address
                : null;
    }

    private static Uri? Endpoint(JsonDocument metadata, string name) =>
        metadata.RootElement.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
        && Uri.TryCreate(value.GetString(), UriKind.Absolute, out var endpoint)
            ? endpoint
            : null;

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
