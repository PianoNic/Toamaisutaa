using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Signs the short-lived access token a local sign-in returns.
/// </summary>
/// <remarks>
/// The claim names are the same ones the claims mapper reads from an identity provider's token, so
/// a locally issued token is indistinguishable to everything downstream: same policies, same
/// <c>ICurrentUser</c>, same provisioning. HS256 from <c>LocalLogin:SigningKey</c> by default,
/// because the only thing that validates these is usually the process that signed them; asymmetric
/// from <c>LocalLogin:SigningKeys</c> when something else has to validate them without being handed
/// the ability to mint them.
/// </remarks>
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

        // The subject is the local user id. That, together with the issuer, is what lets
        // provisioning recognise its own token instead of treating it as a stranger and creating a
        // second user for the same person.
        var claims = new List<Claim> { new(names.Subject, user.Id.ToString()) };

        Add(claims, names.UserName, user.UserName);
        Add(claims, names.Email, user.Email);
        Add(claims, names.DisplayName, user.DisplayName);
        Add(claims, names.Picture, user.PictureUrl);

        foreach (var role in request.Roles)
            Add(claims, oidcOptions.Value.RoleClaim, role);

        // The stamp travels with the token so the two places that do enforce it - refresh, and
        // ICurrentUser - have something to compare without a second lookup.
        Add(claims, ToamaisutaaDefaults.SecurityStampClaim, user.SecurityStamp);

        // RFC 8176. One claim per method, which is how a JWT carries a string array, and how
        // anything that already reads amr expects to find it.
        foreach (var method in request.AuthenticationMethods)
            Add(claims, ToamaisutaaDefaults.AuthenticationMethodClaim, method);

        if (request.TwoFactorEnrolmentRequired)
            Add(claims, ToamaisutaaDefaults.TwoFactorRequiredClaim, "true");

        Add(claims, ToamaisutaaDefaults.TwoFactorSourceClaim, request.TwoFactorSource);

        // The refresh family, which is what "session" means here. Step-up reads it to find the row
        // to elevate - and to elevate that one rather than every session the user has open.
        if (request.SessionId is { } sessionId)
            Add(claims, ToamaisutaaDefaults.SessionIdClaim, sessionId.ToString());

        // Unix seconds, so a policy can subtract it from now without parsing a date format. For a
        // device-trusted sign-in this is the original live challenge, which is the whole point.
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
            // A unique id per token, so a future revocation list has something to name.
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
