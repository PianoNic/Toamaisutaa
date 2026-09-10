using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenApi;

/// <summary>
/// Where the browser sends the user, and where the code is exchanged, read from the issuer's
/// discovery document.
/// </summary>
/// <remarks>
/// Read, never derived. Appending <c>/protocol/openid-connect/auth</c> to the authority is right
/// for Keycloak and wrong for every other issuer, and it fails silently: the document generates,
/// the Authorize button appears, and it points at a URL that has never existed. Discovery is the
/// one answer that is correct for Keycloak, Authentik, Pocket ID, Okta and Entra alike.
/// </remarks>
internal static class AuthorizationServerMetadata
{
    /// <summary>An unreachable issuer must not hang the document. Long enough for a slow issuer on
    /// the same network, short enough that nobody wonders whether the page is loading.</summary>
    private static readonly TimeSpan DiscoveryTimeout = TimeSpan.FromSeconds(5);

    public static async Task<(Uri AuthorizationUrl, Uri TokenUrl)?> DiscoverAsync(
        ToamaisutaaOidcOptions settings,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        // Nothing configured means a deployment that only issues its own tokens. There is no
        // authorization server to describe, and the bearer scheme already covers what it has.
        if (MetadataAddress(settings) is not { } address)
            return null;

        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Toamaisutaa.OpenApi");

        // The bearer handler's rule, applied to the same fetch rather than restated as a second
        // policy: metadata over plaintext is refused unless the deployment has said otherwise.
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

        // The request this is serving may outlive the issuer's willingness to answer.
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

            return (authorization, token);
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
    /// The same address the bearer handler discovers against: <c>Oidc:InternalAuthority</c> where
    /// one is set, because a container reaches its issuer at an address the browser never sees. The
    /// endpoints inside the document are the issuer's public ones either way, which is what the
    /// browser needs.
    /// </summary>
    /// <remarks>
    /// <c>Toamaisutaa.OpenIdConnect</c> has the same three lines in <c>DiscoveryAddress</c>.
    /// Referencing that package from here to share them would put JwtBearer in the dependency graph
    /// of a documentation package, which costs more than the duplication does.
    /// </remarks>
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
