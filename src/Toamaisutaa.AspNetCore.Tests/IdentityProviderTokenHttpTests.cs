using System.Net;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
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
    private static Task<TestApp> StartAsync(
        RSA identityProviderKey,
        ECDsa localKey,
        Action<IServiceCollection>? configureServices = null,
        Action<IEndpointRouteBuilder>? mapExtra = null,
        bool fetchUserInfo = false)
    {
        var discovered = new OpenIdConnectConfiguration
        {
            Issuer = IdentityProvider,
            UserInfoEndpoint = $"{IdentityProvider}/userinfo",
        };

        discovered.SigningKeys.Add(new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId });

        return TestApp.StartAsync(
            configure: settings =>
            {
                settings["Oidc:Authority"] = IdentityProvider;

                // Off unless asked for: most of these tests are about which key validates a
                // signature, and the stand-in has no userinfo endpoint to answer on.
                settings["Oidc:FetchClaimsFromUserInfo"] = fetchUserInfo ? "true" : "false";

                settings.Remove("LocalLogin:SigningKey");
                settings["LocalLogin:SigningKeys:0:Kid"] = LocalKeyId;
                settings["LocalLogin:SigningKeys:0:Pem"] = localKey.ExportPkcs8PrivateKeyPem();
            },
            configureServices: services =>
            {
                services.PostConfigure<JwtBearerOptions>(
                    JwtBearerDefaults.AuthenticationScheme,
                    options => options.ConfigurationManager =
                        new StaticConfigurationManager<OpenIdConnectConfiguration>(discovered));

                configureServices?.Invoke(services);
            },
            mapExtra: mapExtra);
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
                .. extra.Any(claim => claim.Type == "preferred_username") ? [] : new[] { new Claim("preferred_username", "grace") },
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
    /// The provider's email is only what the provider asserted. A first password used to copy it
    /// onto the credential as a login identifier and a reset address, for a mailbox nobody had shown
    /// this account owns.
    /// </summary>
    [Test]
    public async Task A_first_password_does_not_make_the_providers_email_a_login_identifier()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };

        var fresh = Mint(
            app,
            key,
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            "grace-subject",
            AuthTime(app.Time.Now.AddMinutes(-1)),
            new Claim("email", "victim@example.com"));

        var set = await app.Client.PostJson("/auth/password", new { newPassword = Account.DefaultPassword }, fresh);
        await Assert.That(set.StatusCode).IsEqualTo(HttpStatusCode.NoContent);

        var byEmail = await app.Client.PostJson("/auth/login", new { identifier = "victim@example.com", password = Account.DefaultPassword });
        var byUserName = await app.Client.PostJson("/auth/login", new { identifier = "grace", password = Account.DefaultPassword });

        await Assert.That(byEmail.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(byUserName.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// A provider's handle is often an address - a UPN is one. Copied into the user-name column by a
    /// first password, it became a hold on that address that proving the mailbox could never release,
    /// and it answered sign-ins for that address with this account.
    /// </summary>
    [Test]
    public async Task A_first_password_does_not_take_an_address_shaped_user_name_from_the_provider()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };

        var fresh = Mint(
            app,
            key,
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            "grace-subject",
            AuthTime(app.Time.Now.AddMinutes(-1)),
            new Claim("preferred_username", "newhire@example.com"));

        var set = await app.Client.PostJson("/auth/password", new { newPassword = Account.DefaultPassword }, fresh);
        await Assert.That(set.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);

        var byAddress = await app.Client.PostJson("/auth/login", new { identifier = "newhire@example.com", password = Account.DefaultPassword });
        await Assert.That(byAddress.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
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

    /// <summary>
    /// A user who once enrolled locally, signing in through a provider that asked for nothing more
    /// than a password. The transformation used to write <c>amr=mfa</c> for them, and the
    /// second-factor policy let a phished provider password straight through.
    /// </summary>
    /// <remarks>
    /// Run under the default provider key and a configured one. The transformation used to look the
    /// login up under the default constant, so with any other key it found no enrolment at all.
    /// </remarks>
    [Test]
    [Arguments(null)]
    [Arguments("keycloak")]
    public async Task A_local_enrolment_does_not_satisfy_the_second_factor_policy_for_a_provider_sign_in(string? providerKey)
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(
            identityProviderKey,
            localKey,
            services =>
            {
                services.AddToamaisutaaTwoFactorClaims();

                if (providerKey is not null)
                    services.Configure<ToamaisutaaProvisioningOptions>(options => options.ProviderKey = providerKey);
            },
            endpoints =>
            {
                endpoints.MapGet("/test/second-factor", () => "ok").RequireAuthorization("Toamaisutaa.TwoFactor");
                endpoints.MapGet("/test/claims", (ClaimsPrincipal user) =>
                    user.Claims.Select(claim => new { claim.Type, claim.Value }));
            });

        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };
        var fresh = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddMinutes(-1)));

        var begin = await app.Client.PostEmpty("/auth/2fa/begin", fresh);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, fresh);
        await Assert.That(confirm.StatusCode).IsEqualTo(HttpStatusCode.OK);

        // A later sign-in at the provider, which says nothing about how it was proved.
        var later = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject");

        var guarded = await app.Client.Get("/test/second-factor", later);
        await Assert.That(guarded.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);

        var claims = (await (await app.Client.Get("/test/claims", later)).Json()).EnumerateArray()
            .Select(claim => (Type: claim.String("type"), Value: claim.String("value")))
            .ToList();

        await Assert.That(claims).Contains((ToamaisutaaDefaults.TwoFactorEnrolledClaim, "true"));
        await Assert.That(claims.Any(claim => claim.Type == ToamaisutaaDefaults.AuthenticationMethodClaim)).IsFalse();
    }

    /// <summary>
    /// A local token carries no role until an application supplies one, which is exactly what used
    /// to send it to the provider's userinfo endpoint - a credential this package minted, handed to a
    /// third party as a bearer token on every request. A provider token still goes, which is what
    /// shows the call is wired at all.
    /// </summary>
    [Test]
    public async Task A_local_token_is_never_sent_to_the_providers_userinfo_endpoint()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var userInfo = new UserInfoRecorder();

        await using var app = await StartAsync(
            identityProviderKey,
            localKey,
            services => services
                .AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => userInfo),
            fetchUserInfo: true);

        var local = await Account.RegisterAsync(app);
        await Assert.That((await app.Client.Get("/test/me", local.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(userInfo.BearerTokens).DoesNotContain(local.AccessToken);

        var provider = Mint(
            app,
            new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId },
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            "grace-subject");

        await app.Client.Get("/test/me", provider);
        await Assert.That(userInfo.BearerTokens).Contains(provider);
    }

    /// <summary>
    /// With no API audience configured, the accepted audience is the client id - which is what every
    /// ID token for that client carries. ID tokens leak further than access tokens do, through
    /// logout URLs and components that were handed one, and a leaked one signed its subject in.
    /// </summary>
    [Test]
    [Arguments("nonce", "n-0S6_WzA2Mj")]
    [Arguments("at_hash", "77QmUPtjPfzWtF2AnpK9RQ")]
    [Arguments("typ", "ID")]
    public async Task An_id_token_is_refused_as_a_bearer_token(string marker, string value)
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);

        var idToken = Mint(
            app,
            new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId },
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            Guid.NewGuid().ToString(),
            new Claim(marker, value));

        var response = await app.Client.Get("/test/me", idToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// An account the identity provider owns has no password credential, which is where the wrong-code
    /// count lived. A stolen provider token could guess the code at these endpoints as fast as the
    /// per-address limiter allowed, and a right guess paid out the second factor itself.
    /// </summary>
    [Test]
    [Arguments("/auth/2fa/disable")]
    [Arguments("/auth/2fa/recovery-codes")]
    public async Task Wrong_proofs_on_an_account_without_a_password_lock_it(string path)
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };
        var token = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddMinutes(-1)));

        var begin = await app.Client.PostEmpty("/auth/2fa/begin", token);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, token);

        for (var i = 0; i < 5; i++)
        {
            app.Time.AdvanceToNextTotpStep();
            var code = Totp.Code(secret, app.Time.Now);
            var wrong = (char)('0' + ((code[0] - '0' + 1) % 10)) + code[1..];

            await app.Client.PostJson(path, new { proof = wrong }, token);
        }

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson(path, new { proof = Totp.Code(secret, app.Time.Now) }, token);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", token)).Json().Result.Bool("enabled")).IsTrue();
    }

    /// <summary>
    /// The same, raced. Written back unconditionally, parallel wrong proofs all read the same count
    /// and wrote the same count plus one, and the lock never arrived.
    /// </summary>
    [Test]
    public async Task Parallel_wrong_proofs_on_an_account_without_a_password_still_lock_it()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };
        var token = Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", AuthTime(app.Time.Now.AddMinutes(-1)));

        var begin = await app.Client.PostEmpty("/auth/2fa/begin", token);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, token);

        app.Time.AdvanceToNextTotpStep();
        var code = Totp.Code(secret, app.Time.Now);
        var wrong = (char)('0' + ((code[0] - '0' + 1) % 10)) + code[1..];

        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            app.Client.PostJson("/auth/2fa/recovery-codes", new { proof = wrong }, token)));

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson("/auth/2fa/recovery-codes", new { proof = Totp.Code(secret, app.Time.Now) }, token);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    /// <summary>
    /// Keycloak before version 25 put <c>nonce</c> into access tokens as well as ID tokens, and labels
    /// both with a <c>typ</c> claim. Refusing on <c>nonce</c> refused every access token those servers
    /// issued; the label says which kind a token is, and decides.
    /// </summary>
    [Test]
    public async Task A_keycloak_access_token_carrying_nonce_is_accepted_by_its_bearer_label()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);

        var accessToken = Mint(
            app,
            new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId },
            SecurityAlgorithms.RsaSha256,
            IdentityProvider,
            Guid.NewGuid().ToString(),
            new Claim("typ", "Bearer"),
            new Claim("nonce", "n-0S6_WzA2Mj"));

        var response = await app.Client.Get("/test/me", accessToken);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Relying_on_the_client_id_as_the_audience_is_warned_about_at_startup()
    {
        var warnings = new System.Collections.Concurrent.ConcurrentQueue<string>();

        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(
            identityProviderKey,
            localKey,
            services => services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(new StartupWarnings(warnings)));

        await Assert.That(warnings.Count(message => message.Contains("Oidc:ValidAudiences"))).IsEqualTo(1);
    }

    private sealed class StartupWarnings(System.Collections.Concurrent.ConcurrentQueue<string> warnings) : Microsoft.Extensions.Logging.ILoggerProvider
    {
        public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Collector(warnings);

        public void Dispose()
        {
        }

        private sealed class Collector(System.Collections.Concurrent.ConcurrentQueue<string> warnings) : Microsoft.Extensions.Logging.ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => logLevel >= Microsoft.Extensions.Logging.LogLevel.Warning;

            public void Log<TState>(
                Microsoft.Extensions.Logging.LogLevel logLevel,
                Microsoft.Extensions.Logging.EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel))
                    warnings.Enqueue(formatter(state, exception));
            }
        }
    }

    /// <summary>A provider token with an email and no <c>preferred_username</c> - Google's shape - which
    /// provisions a row with no user name and no password: exactly what a reservation used to look like.</summary>
    private static string MintWithoutUserName(TestApp app, SecurityKey key, string subject, string email) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = IdentityProvider,
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("email", email)]),
            IssuedAt = app.Time.Now.UtcDateTime,
            NotBefore = app.Time.Now.UtcDateTime,
            Expires = app.Time.Now.AddMinutes(15).UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        });

    /// <summary>
    /// Revoking read "no user name, no password" as "an open invitation", so it deleted an identity
    /// provider's account that happened to have that shape - along with its logins and sessions.
    /// </summary>
    [Test]
    public async Task Revoking_an_invitation_never_deletes_an_identity_provider_account()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var google = MintWithoutUserName(app, key, "google-subject", "alice@example.org");
        var before = await (await app.Client.Get("/test/me", google)).Json();

        var revoked = await app.Client.PostJson("/auth/invitations/revoke", new { email = "alice@example.org" }, admin.AccessToken);
        var after = await app.Client.Get("/test/me", google);

        await Assert.That(revoked.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That((await after.Json()).String("id")).IsEqualTo(before.String("id"));
    }

    /// <summary>
    /// Inviting the address of such an account reused its row, so the invitee's new password was
    /// attached to an account somebody else's provider login still opened.
    /// </summary>
    [Test]
    public async Task An_invitation_never_adopts_an_identity_provider_account()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var app = await StartAsync(identityProviderKey, localKey);
        var key = new RsaSecurityKey(identityProviderKey) { KeyId = IdentityProviderKeyId };
        var admin = await Account.RegisterAsync(app, TestApp.AdminUserName);

        var google = MintWithoutUserName(app, key, "google-subject", "newhire@example.org");
        var providerAccount = (await (await app.Client.Get("/test/me", google)).Json()).String("id");

        await app.Client.PostJson("/auth/invitations", new { email = "newhire@example.org" }, admin.AccessToken);

        var completed = await app.Client.PostJson(
            "/auth/invitations/complete",
            new { token = app.IssuedInvitations.Single().Token, userName = "newhire", password = Account.DefaultPassword });

        var invitedAccount = Account.DecodeClaims((await completed.Json()).String("access_token")!).String("sub");

        await Assert.That(completed.StatusCode).IsEqualTo(HttpStatusCode.Created);
        await Assert.That(invitedAccount).IsNotEqualTo(providerAccount);
    }

    private sealed class UserInfoRecorder : HttpMessageHandler
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> BearerTokens { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            BearerTokens.Enqueue(request.Headers.Authorization?.Parameter ?? string.Empty);

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }

    private static Claim AuthTime(DateTimeOffset at) =>
        new("auth_time", at.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);
}
