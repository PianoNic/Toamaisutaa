using Microsoft.AspNetCore.Http;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore;

/// <summary>
/// Builds the SPA's runtime OIDC configuration, so an application can serve its own fields alongside
/// it without rebuilding the redirect-URI resolution.
/// </summary>
public interface IToamaisutaaClientConfigurationProvider
{
    ToamaisutaaClientConfiguration GetConfiguration(HttpContext context);
}
