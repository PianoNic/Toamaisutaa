using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Uses the claim names the claims mapper reads from an identity provider's token, so a local token
/// is indistinguishable to policies, <c>ICurrentUser</c> and provisioning.
/// </summary>
internal sealed class LocalAccessTokenIssuer(
    IOptions<ToamaisutaaLocalLoginOptions> localOptions,
    IOptions<ToamaisutaaOidcOptions> oidcOptions,
    IOptions<ToamaisutaaProvisioningOptions> provisioningOptions,
    LocalTokenKeys keys,
    TimeProvider timeProvider) : IAccessTokenIssuer
{
    private readonly JsonWebTokenHandler _handler = new();

    public Task<AccessToken> IssueAsync(AccessTokenRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var user = request.User;
        var local = localOptions.Value;
        var names = provisioningOptions.Value.ClaimNames;

        var now = timeProvider.GetUtcNow();
        var expires = now + local.AccessTokenLifetime;

        // The local user id with the local issuer is what stops provisioning creating a second user for this token.
        var claims = new List<Claim> { new(names.Subject, user.Id.ToString()) };

        Add(claims, names.UserName, user.UserName);
        Add(claims, names.Email, request.VerifiedEmail);
        Add(claims, names.DisplayName, user.DisplayName);
        Add(claims, names.Picture, user.PictureUrl);

        foreach (var role in request.Roles)
            Add(claims, oidcOptions.Value.RoleClaim, role);

        // Refresh and ICurrentUser compare this against the stored stamp.
        Add(claims, ToamaisutaaDefaults.SecurityStampClaim, user.SecurityStamp);

        // RFC 8176 amr: one claim per method, which is how a JWT carries a string array.
        foreach (var method in request.AuthenticationMethods)
            Add(claims, ToamaisutaaDefaults.AuthenticationMethodClaim, method);

        if (request.TwoFactorEnrolmentRequired)
            Add(claims, ToamaisutaaDefaults.TwoFactorRequiredClaim, "true");

        Add(claims, ToamaisutaaDefaults.TwoFactorSourceClaim, request.TwoFactorSource);

        // The refresh family: step-up reads it to elevate this session rather than every one the user has open.
        if (request.SessionId is { } sessionId)
            Add(claims, ToamaisutaaDefaults.SessionIdClaim, sessionId.ToString());

        // For a device-trusted sign-in this is the original live challenge, not now.
        if (request.SecondFactorAt is { } secondFactorAt)
        {
            Add(
                claims,
                ToamaisutaaDefaults.SecondFactorAtClaim,
                secondFactorAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = local.Issuer,
            Audience = ResolveAudience(local, oidcOptions.Value),
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = keys.Signing
                ?? throw new InvalidOperationException(
                    "Neither LocalLogin:SigningKey nor LocalLogin:SigningKeys is configured, so no token can be signed."),
            TokenType = "at+jwt",
        };

        return Task.FromResult(new AccessToken(_handler.CreateToken(descriptor), expires));
    }

    internal static string? ResolveAudience(ToamaisutaaLocalLoginOptions local, ToamaisutaaOidcOptions oidc) =>
        string.IsNullOrWhiteSpace(local.Audience) ? NullIfBlank(oidc.ClientId) : local.Audience;

    private static void Add(List<Claim> claims, string type, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            claims.Add(new Claim(type, value));
    }

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
