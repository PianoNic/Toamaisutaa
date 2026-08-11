using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Everything <c>AddToamaisutaaBearer</c> configures on the JwtBearer handler. Written as an
/// options configurator rather than inline so the enricher and the logger come from DI.
/// </summary>
internal sealed class ConfigureToamaisutaaJwtBearerOptions(
    IOptions<ToamaisutaaOidcOptions> oidcOptions,
    IOptions<ToamaisutaaAuthorizationOptions> authorizationOptions,
    UserInfoClaimsEnricher enricher) : IConfigureNamedOptions<JwtBearerOptions>
{
    public void Configure(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
            return;

        Configure(options);
    }

    public void Configure(JwtBearerOptions options)
    {
        var settings = oidcOptions.Value;

        var publicAuthority = NullIfBlank(settings.Authority);
        var internalAuthority = NullIfBlank(settings.InternalAuthority) ?? publicAuthority;

        options.Authority = publicAuthority;

        // Reaching the issuer at a different address than the one it stamps into tokens is normal
        // inside a container network. Discovery moves; the issuer check does not.
        if (internalAuthority is not null && !string.Equals(internalAuthority, publicAuthority, StringComparison.Ordinal))
            options.MetadataAddress = $"{internalAuthority.TrimEnd('/')}/.well-known/openid-configuration";

        options.RequireHttpsMetadata = settings.RequireHttpsMetadata;

        // Not configurable. Remapping claim types to WS-Federation URIs while every other setting
        // names raw JWT claims is how two of the four codebases this replaces ended up with a
        // NameClaimType that matched nothing.
        options.MapInboundClaims = false;

        options.TokenValidationParameters.NameClaimType = settings.NameClaim;
        options.TokenValidationParameters.RoleClaimType = settings.RoleClaim;
        options.TokenValidationParameters.ValidateIssuer = settings.ValidateIssuer;
        options.TokenValidationParameters.ValidIssuer = publicAuthority;
        options.TokenValidationParameters.ValidateAudience = settings.ValidateAudience;
        options.TokenValidationParameters.ValidAudiences = ValidAudiences(settings);

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ReadQueryToken(settings.QueryToken),
            OnTokenValidated = enricher.EnrichAsync,
            OnForbidden = ExplainForbidden(settings, authorizationOptions.Value),
        };
    }

    internal static IReadOnlyList<string> ValidAudiences(ToamaisutaaOidcOptions settings)
    {
        if (settings.ValidAudiences.Count > 0)
            return [.. settings.ValidAudiences];

        return NullIfBlank(settings.ClientId) is { } clientId ? [clientId] : [];
    }

    /// <summary>
    /// Browsers cannot set an Authorization header on a WebSocket handshake, so SignalR passes the
    /// token as a query parameter. Honoured only on the configured paths, because a token in a
    /// query string ends up in access logs.
    /// </summary>
    private static Func<MessageReceivedContext, Task> ReadQueryToken(ToamaisutaaQueryTokenOptions queryToken)
    {
        var include = Normalise(queryToken.IncludePaths);
        var exclude = Normalise(queryToken.ExcludePaths);

        return context =>
        {
            if (include.Count == 0)
                return Task.CompletedTask;

            var path = context.HttpContext.Request.Path;

            if (!include.Any(path.StartsWithSegments) || exclude.Any(path.StartsWithSegments))
                return Task.CompletedTask;

            var token = context.Request.Query[queryToken.ParameterName];
            if (!string.IsNullOrEmpty(token))
                context.Token = token;

            return Task.CompletedTask;
        };
    }

    private static List<PathString> Normalise(IEnumerable<string> paths) =>
        [.. paths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => new PathString(path.StartsWith('/') ? path.TrimEnd('/') : "/" + path.Trim('/')))];

    /// <summary>
    /// A 403 here means the token was accepted and the role was not found, which is invisible from
    /// the outside: an empty body, and a valid login. Say which claim was read and what the token
    /// actually carried, because that pair is the whole answer.
    /// </summary>
    private static Func<ForbiddenContext, Task> ExplainForbidden(
        ToamaisutaaOidcOptions settings,
        ToamaisutaaAuthorizationOptions authorization) =>
        context =>
        {
            // HttpContext.User, not context.Principal: the handler builds ForbiddenContext without a
            // principal, so reading it reports a token with no claims at all and sends whoever is
            // debugging looking for the wrong problem.
            var user = context.HttpContext.User;

            var carried = user.Claims
                .Where(claim => string.Equals(claim.Type, settings.RoleClaim, StringComparison.Ordinal))
                .Select(claim => claim.Value)
                .ToList();

            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("Toamaisutaa.Auth");

            logger.LogWarning(
                "{Path} refused: the token is valid but carries no {Role} in its '{Claim}' claim. "
                + "It carries [{Carried}] there, and these claim types: [{Types}]. "
                + "Set Oidc:RoleClaim if your issuer publishes membership somewhere else.",
                context.HttpContext.Request.Path,
                authorization.AdminRole ?? "(no admin role configured)",
                settings.RoleClaim,
                string.Join(", ", carried),
                string.Join(", ", user.Claims.Select(claim => claim.Type).Distinct()));

            return Task.CompletedTask;
        };

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
