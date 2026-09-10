using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The path the whole package is for: an access token the identity provider issued, presented to an
/// application that also registers password login.
/// </summary>
/// <remarks>
/// <para>
/// No identity provider is run and nothing is fetched. A <c>StaticConfigurationManager</c> stands in
/// for one, which is not a shortcut but the point: it is a <c>BaseConfigurationManager</c>, exactly
/// like the manager the handler builds for an <c>Oidc:Authority</c> once discovery has answered, and
/// that is the distinction that matters. For one of those the handler hands the issuer's keys to the
/// validator as the configuration and never merges them into <c>IssuerSigningKeys</c>.
/// </para>
/// <para>
/// Nothing here presented an identity-provider token before, so a key resolver that could only read
/// <c>IssuerSigningKeys</c> refused every one of them in the package's primary configuration while
/// the suite stayed green. The two refusals below are the other half: the resolver still has to keep
/// each issuer to its own keys.
/// </para>
/// </remarks>
public class IdentityProviderTokenHttpTests
{
    private const string IdentityProvider = "https://idp.example";
    private const string IdentityProviderKeyId = "idp-2026-09";
    private const string LocalKeyId = "local-2026-09";
    private const string LocalIssuer = "toamaisutaa-tests";

    /// <summary>
    /// A host that trusts <see cref="IdentityProvider"/> for its RSA key and itself for a local EC
    /// key, which is the deployment shape the break needed: with no local keys configured the bearer
    /// options are left exactly as the handler wrote them and the resolver is never installed.
    /// </summary>
    private static Task<TestApp> StartAsync(RSA identityProviderKey, ECDsa localKey)
    {
        var discovered = new OpenIdConnectConfiguration { Issuer = IdentityProvider };
        discovered.SigningKeys.Add(new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId });

        return TestApp.StartAsync(
            configure: settings =>
            {
                settings["Oidc:Authority"] = IdentityProvider;

                // The enricher would otherwise ask the stand-in for a userinfo endpoint it has no
                // reason to publish. These tests are about which key validates a signature.
                settings["Oidc:FetchClaimsFromUserInfo"] = "false";

                settings.Remove("LocalLogin:SigningKey");
                settings["LocalLogin:SigningKeys:0:Kid"] = LocalKeyId;
                settings["LocalLogin:SigningKeys:0:Pem"] = localKey.ExportPkcs8PrivateKeyPem();
            },
            configureServices: services => services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme,
                options => options.ConfigurationManager =
                    new StaticConfigurationManager<OpenIdConnectConfiguration>(discovered)));
    }

    /// <summary>
    /// Minted rather than doctored, for the reason <c>TestApp.MintTokenWithoutSession</c> gives:
    /// editing a real token breaks its signature, so the request never reaches the code under test.
    /// </summary>
    private static string Mint(TestApp app, SecurityKey key, string algorithm, string issuer, string subject) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity(
            [
                new Claim("sub", subject),
                new Claim("preferred_username", "grace"),
            ]),
            IssuedAt = app.Time.Now.UtcDateTime,
            NotBefore = app.Time.Now.UtcDateTime,
            Expires = app.Time.Now.AddMinutes(15).UtcDateTime,
            SigningCredentials = new SigningCredentials(key, algorithm),
        });

    [Test]
    public async Task Accepts_a_token_the_identity_provider_signed()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);

        var token = Mint(
            app,
            new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId },
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            Guid.NewGuid().ToString());

        var response = await app.Client.Get("/test/me", token);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await response.Json()).String("userName")).IsEqualTo("grace");
    }

    /// <summary>
    /// The first half of the defence the resolver exists for. A token claiming the identity
    /// provider and signed with a key this package owns is somebody who reached our signing key
    /// trying to pass as the issuer, and the local keys must never be offered for it.
    /// </summary>
    [Test]
    public async Task Refuses_an_identity_provider_token_signed_with_the_local_key()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);

        var token = Mint(
            app,
            new ECDsaSecurityKey(localKey) { KeyId = LocalKeyId },
            SecurityAlgorithms.EcdsaSha256,
            IdentityProvider,
            Guid.NewGuid().ToString());

        var response = await app.Client.Get("/test/me", token);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// The other half, and the worse of the two: a token claiming the local issuer carries a local
    /// user id as its subject, so accepting one signed by the identity provider's key would hand
    /// whoever can mint an IdP token any account in the database.
    /// </summary>
    [Test]
    public async Task Refuses_a_local_token_signed_with_the_identity_provider_key()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);

        var token = Mint(
            app,
            new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId },
            SecurityAlgorithms.RsaSha256,
            LocalIssuer,
            Guid.NewGuid().ToString());

        var response = await app.Client.Get("/test/me", token);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }
}
