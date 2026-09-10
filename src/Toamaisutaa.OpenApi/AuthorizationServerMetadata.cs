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
    /// Moves an endpoint the issuer answered with under <c>Oidc:InternalAuthority</c> back onto
    /// <c>Oidc:Authority</c>, keeping the path the discovery document gave it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The fetch goes over the internal address because that is how a container reaches its issuer,
    /// and what comes back is usually the public URLs. Usually is not always: an issuer that builds
    /// its endpoint URLs from the request's Host header - Keycloak with no <c>KC_HOSTNAME</c> - hands
    /// the internal hop the internal host, and that host is written into the document as a button a
    /// browser is asked to follow. It cannot resolve it. That is the same dead Authorize button this
    /// package exists to remove, reached from the other side.
    /// </para>
    /// <para>
    /// So an endpoint that is provably under the internal authority is moved, and nothing else is.
    /// <c>Oidc:Authority</c> is the right destination rather than a guess: it is what the
    /// configuration endpoint already hands the SPA, so the Authorize button and the SPA end up
    /// pointing at the same issuer. An endpoint on some third host is left exactly as discovered -
    /// an issuer whose authorization endpoint lives on a separate login domain is ordinary, and
    /// rewriting or dropping that would break a deployment that works today.
    /// </para>
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

        // A shared host is not enough. Where the internal authority carries a path - one realm of
        // several - an endpoint outside it belongs to something this setting says nothing about.
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
    /// The same address the bearer handler discovers against: <c>Oidc:InternalAuthority</c> where
    /// one is set, because a container reaches its issuer at an address the browser never sees.
    /// What comes back is put in front of a browser, so see <see cref="PublicFacing"/> for the half
    /// of that the bearer handler does not need.
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
