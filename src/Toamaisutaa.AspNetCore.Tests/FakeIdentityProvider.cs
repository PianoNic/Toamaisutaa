using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An OpenID Connect provider written from the specification, answering discovery, keys and the token
/// endpoint in process. It checks what a real one checks - the client, the redirect address and the
/// PKCE verifier - so a relying party that skips one fails here as it would against Google.
/// </summary>
/// <remarks>
/// Never disposed: the HTTP client factory disposes primary handlers when it rotates them, and this one
/// outlives any one of them.
/// </remarks>
internal sealed class FakeIdentityProvider(string? tenant = null) : HttpMessageHandler
{
    /// <summary>What Microsoft's multi-tenant endpoints publish in place of an issuer.</summary>
    public const string TenantIssuerTemplate = $"{Authority}/{{tenantid}}/v2.0";

    public const string Authority = "https://idp.test";
    public const string ClientId = "toamaisutaa-client";
    public const string ClientSecret = "client-secret";
    private const string KeyId = "idp-key";

    private readonly RSA _key = RSA.Create(2048);
    private readonly Dictionary<string, Grant> _grants = new(StringComparer.Ordinal);

    public List<IReadOnlyDictionary<string, string>> TokenRequests { get; } = [];

    /// <summary>What the browser does at the provider: signs the user in and comes back with a code.</summary>
    public string Authorize(string authorizationUrl, Person person, Tamper tamper = default)
    {
        var query = QueryHelpers.ParseQuery(new Uri(authorizationUrl).Query);

        if (!authorizationUrl.StartsWith($"{Authority}/authorize?", StringComparison.Ordinal)
            || query["response_type"] != "code"
            || query["client_id"] != ClientId
            || query["code_challenge_method"] != "S256"
            || string.IsNullOrEmpty(query["code_challenge"])
            || string.IsNullOrEmpty(query["nonce"])
            || string.IsNullOrEmpty(query["state"]))
        {
            throw new InvalidOperationException($"Not an authorization request this provider would accept: {authorizationUrl}");
        }

        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        _grants[code] = new Grant(
            person,
            tamper,
            query["redirect_uri"]!,
            query["code_challenge"]!,
            tamper.Nonce ?? query["nonce"]!);

        return QueryHelpers.AddQueryString(query["redirect_uri"]!, new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = query["state"],
        });
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.GetLeftPart(UriPartial.Path);

        if (path == $"{Authority}/.well-known/openid-configuration")
        {
            return JsonReply(new
            {
                issuer = tenant is null ? Authority : TenantIssuerTemplate,
                authorization_endpoint = $"{Authority}/authorize",
                token_endpoint = $"{Authority}/token",
                jwks_uri = $"{Authority}/jwks",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
            });
        }

        if (path == $"{Authority}/jwks")
        {
            var parameters = _key.ExportParameters(includePrivateParameters: false);

            return JsonReply(new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        kid = KeyId,
                        n = Base64UrlEncoder.Encode(parameters.Modulus),
                        e = Base64UrlEncoder.Encode(parameters.Exponent),
                    },
                },
            });
        }

        if (path == $"{Authority}/token" && request.Method == HttpMethod.Post)
            return Token(QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken)).ToDictionary(pair => pair.Key, pair => pair.Value.ToString()));

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private HttpResponseMessage Token(Dictionary<string, string> form)
    {
        lock (TokenRequests)
            TokenRequests.Add(form);

        // Single use, as RFC 6749 requires.
        if (!form.TryGetValue("code", out var code) || !_grants.Remove(code, out var grant))
            return Error("invalid_grant");

        if (form.GetValueOrDefault("grant_type") != "authorization_code"
            || form.GetValueOrDefault("client_id") != ClientId
            || form.GetValueOrDefault("client_secret") != ClientSecret
            || form.GetValueOrDefault("redirect_uri") != grant.RedirectUri)
        {
            return Error("invalid_client");
        }

        // RFC 7636 4.6, written out here rather than borrowed from the package.
        var verifier = form.GetValueOrDefault("code_verifier") ?? string.Empty;
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        if (challenge != grant.CodeChallenge)
            return Error("invalid_grant");

        return JsonReply(new { access_token = "opaque", token_type = "Bearer", id_token = IdToken(grant) });
    }

    private string IdToken(Grant grant)
    {
        var person = grant.Person;
        var tamper = grant.Tamper;

        var claims = new List<Claim>
        {
            new("sub", person.Subject),
            new("nonce", grant.Nonce),
            new("name", person.Name ?? person.Subject),
            new("preferred_username", person.Subject),
        };

        if (person.Email is not null)
        {
            claims.Add(new Claim("email", person.Email));
            claims.Add(new Claim("email_verified", person.EmailVerified ? "true" : "false", ClaimValueTypes.Boolean));
        }

        if (tenant is not null)
            claims.Add(new Claim("tid", tenant));

        // A provider's own claim that it checked a second factor, which must not be taken at its word.
        claims.Add(new Claim("amr", "mfa"));

        var now = DateTime.UtcNow;
        var signingKey = tamper.ForeignKey
            ? new RsaSecurityKey(RSA.Create(2048)) { KeyId = KeyId }
            : new RsaSecurityKey(_key) { KeyId = KeyId };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = tamper.Issuer ?? (tenant is null ? Authority : $"{Authority}/{tenant}/v2.0"),
            Audience = tamper.Audience ?? ClientId,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = tamper.Expired ? now.AddHours(-2) : now,
            NotBefore = tamper.Expired ? now.AddHours(-2) : now,
            Expires = tamper.Expired ? now.AddHours(-1) : now.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
        });
    }

    private static HttpResponseMessage JsonReply(object body) =>
        new(HttpStatusCode.OK) { Content = JsonContent.Create(body) };

    private static HttpResponseMessage Error(string error) =>
        new(HttpStatusCode.BadRequest) { Content = JsonContent.Create(new { error }) };

    private sealed record Grant(Person Person, Tamper Tamper, string RedirectUri, string CodeChallenge, string Nonce);
}

internal sealed record Person(string Subject, string? Email = null, bool EmailVerified = true, string? Name = null);

/// <summary>Ways a token can be wrong that a relying party has to notice.</summary>
internal readonly record struct Tamper
{
    public string? Nonce { get; init; }

    public string? Audience { get; init; }

    public string? Issuer { get; init; }

    public bool ForeignKey { get; init; }

    public bool Expired { get; init; }
}
