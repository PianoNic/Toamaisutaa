using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

internal sealed class ConfigureToamaisutaaJwtBearerOptions(
    IOptions<ToamaisutaaOidcOptions> oidcOptions,
    IOptions<ToamaisutaaAuthorizationOptions> authorizationOptions,
    IOptions<ToamaisutaaLocalLoginOptions> localLoginOptions,
    LocalTokenKeys localKeys,
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

        // Inside a container network the issuer is reached at another address: discovery moves, the issuer check does not.
        if (internalAuthority is not null && !string.Equals(internalAuthority, publicAuthority, StringComparison.Ordinal))
            options.MetadataAddress = DiscoveryAddress.From(internalAuthority);

        options.RequireHttpsMetadata = settings.RequireHttpsMetadata;

        // Not configurable: remapping to WS-Federation URIs would leave NameClaim and RoleClaim naming
        // claims the principal no longer has, and role checks would silently match nothing.
        options.MapInboundClaims = false;

        options.TokenValidationParameters.NameClaimType = settings.NameClaim;
        options.TokenValidationParameters.RoleClaimType = settings.RoleClaim;
        options.TokenValidationParameters.ValidateIssuer = settings.ValidateIssuer;
        options.TokenValidationParameters.ValidIssuer = publicAuthority;
        options.TokenValidationParameters.ValidateAudience = settings.ValidateAudience;
        options.TokenValidationParameters.ValidAudiences = ValidAudiences(settings, localLoginOptions.Value);

        ConfigureLocallyIssuedTokens(options);

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ReadQueryToken(settings.QueryToken),
            OnTokenValidated = context => RefuseIdTokens(context) ? Task.CompletedTask : enricher.EnrichAsync(context),
            OnForbidden = ExplainForbidden(settings, authorizationOptions.Value),
        };
    }

    /// <summary>
    /// Fails an ID token presented as a bearer token, which the client-id audience fallback would
    /// otherwise accept, and says true when it did.
    /// </summary>
    /// <remarks>
    /// A <c>typ</c> label decides first because Keycloak before 25 put <c>nonce</c> into access tokens;
    /// only an unlabelled token is judged by the OIDC ID-token markers <c>nonce</c> and <c>at_hash</c>.
    /// </remarks>
    internal static bool RefuseIdTokens(TokenValidatedContext context)
    {
        var principal = context.Principal;
        var label = principal?.FindFirst("typ")?.Value;

        var looksLikeIdToken = label is not null
            ? string.Equals(label, "ID", StringComparison.OrdinalIgnoreCase)
            : principal is not null && principal.HasClaim(claim => claim.Type is "nonce" or "at_hash");

        if (!looksLikeIdToken)
            return false;

        context.Fail("An ID token was presented as a bearer token. Send the access token instead.");
        return true;
    }

    internal static IReadOnlyList<string> ValidAudiences(ToamaisutaaOidcOptions settings, ToamaisutaaLocalLoginOptions local)
    {
        var audiences = settings.ValidAudiences.Count > 0
            ? [.. settings.ValidAudiences]
            : NullIfBlank(settings.ClientId) is { } clientId ? new List<string> { clientId } : [];

        // A local audience that differs from the client id would otherwise be rejected by the same
        // process that issued it.
        if (NullIfBlank(local.Audience) is { } localAudience && !audiences.Contains(localAudience, StringComparer.Ordinal))
            audiences.Add(localAudience);

        return audiences;
    }

    /// <summary>
    /// The key resolver binds each issuer to its own keys; in one flat collection a token claiming our
    /// issuer but signed with the identity provider's key would validate as a local user.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The key resolver is the part that matters. With both key sets in one flat collection, the
    /// validator falls back to trying every key when the key id does not match - so a token
    /// claiming our issuer but signed with the identity provider's key would validate, and its
    /// subject is a local user id. Binding each issuer to its own key closes that.
    /// </para>
    /// <para>
    /// It stays closed with a key list rather than a single key: the local branch answers with our
    /// keys picked by <c>kid</c> and never with the issuer's, and the issuer branch drops every key
    /// id we own.
    /// </para>
    /// </remarks>
    private void ConfigureLocallyIssuedTokens(JwtBearerOptions options)
    {
        var local = localLoginOptions.Value;

        if (localKeys.ValidationKeys.Count == 0)
            return;

        options.TokenValidationParameters.ValidIssuers = [local.Issuer];
        options.TokenValidationParameters.IssuerSigningKeys = localKeys.ValidationKeys;

        // By default an empty resolver answer falls back to trying every key, which would undo the
        // issuer-to-key binding below.
        options.TokenValidationParameters.TryAllIssuerSigningKeys = false;

        // Must be the ...UsingConfiguration resolver: discovery keys arrive as the BaseConfiguration, not
        // in IssuerSigningKeys, so the plain resolver would refuse every identity provider token.
        options.TokenValidationParameters.IssuerSigningKeyResolverUsingConfiguration =
            (_, securityToken, keyId, parameters, configuration) =>
                string.Equals(securityToken?.Issuer, local.Issuer, StringComparison.Ordinal)
                    ? localKeys.Resolve(keyId)
                    : IssuerKeys(parameters, configuration);
    }

    /// <summary>
    /// Reads both discovery keys and hand-configured <c>IssuerSigningKeys</c>, minus every key we own.
    /// </summary>
    private IEnumerable<SecurityKey> IssuerKeys(TokenValidationParameters parameters, BaseConfiguration? configuration) =>
        (parameters.IssuerSigningKeys ?? [])
            .Concat(configuration?.SigningKeys ?? [])
            .Where(key => !localKeys.Owns(key.KeyId));

    /// <summary>
    /// Browsers cannot set an Authorization header on a WebSocket handshake, so SignalR passes the
    /// token in the query. Honoured only on configured paths, because query strings reach access logs.
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
    /// A 403 is invisible from outside, so log which claim was read and what the token carried there.
    /// </summary>
    private static Func<ForbiddenContext, Task> ExplainForbidden(
        ToamaisutaaOidcOptions settings,
        ToamaisutaaAuthorizationOptions authorization) =>
        context =>
        {
            // HttpContext.User, not context.Principal: the handler builds ForbiddenContext without a principal.
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
