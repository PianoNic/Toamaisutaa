using System.Net;
using System.Globalization;
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
    private static string Mint(TestApp app, SecurityKey key, string algorithm, string issuer, string subject, params Claim[] extra) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity(
            [
                new Claim("sub", subject),
                new Claim("preferred_username", "grace"),
                .. extra,
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

    /// <summary>
    /// A first password has no current one to prove, so a bare access token used to be enough to add
    /// a permanent way into an identity-provider account - one that survives the provider disabling it.
    /// </summary>
    [Test]
    public async Task A_first_password_is_refused_without_a_recent_sign_in_at_the_identity_provider()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };

        var noAuthTime = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject");
        var staleAuthTime = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddHours(-1)));

        foreach (var token in new[] { noAuthTime, staleAuthTime })
        {
            var response = await app.Client.PostJson("/auth/password", new { newPassword = Account.DefaultPassword }, token);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        }

        var login = await app.Client.PostJson("/auth/login", new { identifier = "grace", password = Account.DefaultPassword });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task A_first_password_is_set_after_a_recent_sign_in_at_the_identity_provider()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };

        var fresh = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddMinutes(-1)));

        var response = await app.Client.PostJson("/auth/password", new { newPassword = Account.DefaultPassword }, fresh);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var login = await app.Client.PostJson("/auth/login", new { identifier = "grace", password = Account.DefaultPassword });
        await Assert.That(login.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// An account an identity provider owns has no password to give, so a recent sign-in there is
    /// the proof enrolment takes instead.
    /// </summary>
    [Test]
    public async Task Enrolling_an_identity_provider_account_needs_a_recent_sign_in_there()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };

        var stale = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddHours(-1)));
        var fresh = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddMinutes(-1)));

        var refused = await app.Client.PostEmpty("/auth/2fa/begin", stale);
        await Assert.That(refused.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var begun = await app.Client.PostEmpty("/auth/2fa/begin", fresh);
        await Assert.That(begun.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    private static Claim AuthTime(DateTimeOffset at) =>
        new("auth_time", at.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);
}
