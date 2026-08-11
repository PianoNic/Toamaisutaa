using Microsoft.AspNetCore.Http;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Builds the SPA's runtime OIDC configuration, including the redirect-URI resolution that is the
/// only part with real logic in it. Public and separate from the endpoint because every application
/// eventually wants to serve its own fields alongside this block, and rebuilding the OIDC half by
/// hand is how four copies of the same code happened in the first place.
/// </summary>
/// <remarks>
/// Lives here rather than in Abstractions because it takes an <see cref="HttpContext"/>: the last
/// fallback for the redirect URI is the request's own origin.
/// </remarks>
public interface IToamaisutaaClientConfigurationProvider
{
    ToamaisutaaClientConfiguration GetConfiguration(HttpContext context);
}
