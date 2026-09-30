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
/// Uses a <c>StaticConfigurationManager</c> because, like the discovery-backed manager, it is a
/// <c>BaseConfigurationManager</c>, whose keys the handler never merges into <c>IssuerSigningKeys</c>.
/// </summary>
public class IdentityProviderTokenHttpTests
{
    private const string IdentityProvider = "https://idp.example";
    private const string IdentityProviderKeyId = "idp-2026-09";
    private const string LocalKeyId = "local-2026-09";
    private const string LocalIssuer = "toamaisutaa-tests";

    /// <summary>Local keys are configured because without them the key resolver under test is never installed.</summary>
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

                // The stand-in issuer has no userinfo endpoint to answer on.
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

    /// <summary>Minted rather than doctored, because editing a real token breaks its signature before the code under test runs.</summary>
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
    /// A local token's subject is a local user id, so accepting the provider's key here would let anyone who can mint an IdP token pick any account.
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
    /// A provider's handle is often an address (a UPN is one), and as a user name it would answer sign-ins for that unproven address.
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
    /// Covers a non-default provider key and a provider-sent <c>amr</c> (as Entra, Okta, Auth0 and Keycloak send), each of which once hid the local enrolment.
    /// </summary>
    [Test]
    [Arguments(null, false)]
    [Arguments("keycloak", false)]
    [Arguments(null, true)]
    public async Task A_local_enrolment_does_not_satisfy_the_second_factor_policy_for_a_provider_sign_in(string? providerKey, bool providerSendsAmr)
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

        var later = providerSendsAmr
            ? Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject", new Claim("amr", "pwd"))
            : Mint(app, key, SecurityAlgorithms.RsaSha256, IdentityProvider, "grace-subject");

        var guarded = await app.Client.Get("/test/second-factor", later);
        await Assert.That(guarded.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);

        var claims = (await (await app.Client.Get("/test/claims", later)).Json()).EnumerateArray()
            .Select(claim => (Type: claim.String("type"), Value: claim.String("value")))
            .ToList();

        await Assert.That(claims).Contains((ToamaisutaaDefaults.TwoFactorEnrolledClaim, "true"));

        await Assert.That(claims.Where(claim => claim.Type == ToamaisutaaDefaults.AuthenticationMethodClaim).Select(claim => claim.Value))
            .IsEquivalentTo(providerSendsAmr ? ["pwd"] : Array.Empty<string?>());
    }

    /// <summary>
    /// A local subject never matches an external login, so the claims cannot show a skipped lookup and the lookup itself is counted.
    /// </summary>
    [Test]
    public async Task A_local_token_costs_the_two_factor_claims_no_lookup()
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var lookups = new CountedLookups();

        await using var app = await StartAsync(identityProviderKey, localKey, services =>
        {
            services.AddToamaisutaaTwoFactorClaims();
            services.Decorate<IExternalLoginStore>(lookups.Wrap);
        });

        var local = await Account.RegisterAsync(app);
        lookups.Reset();

        await Assert.That((await app.Client.Get("/test/me", local.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(lookups.Count).IsEqualTo(0);
    }

    private sealed class CountedLookups
    {
        private int _count;

        internal int Count => Volatile.Read(ref _count);

        internal void Reset() => Interlocked.Exchange(ref _count, 0);

        internal IExternalLoginStore Wrap(IExternalLoginStore inner) => new Counting(this, inner);

        private sealed class Counting(CountedLookups owner, IExternalLoginStore inner) : IExternalLoginStore
        {
            public Task<ToamaisutaaExternalLogin?> FindAsync(string providerKey, string subject, CancellationToken cancellationToken = default)
            {
                Interlocked.Increment(ref owner._count);
                return inner.FindAsync(providerKey, subject, cancellationToken);
            }

            public Task<ToamaisutaaExternalLogin> LinkAsync(Guid userId, string providerKey, ExternalUserProfile profile, CancellationToken cancellationToken = default) =>
                inner.LinkAsync(userId, providerKey, profile, cancellationToken);

            public Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default) =>
                inner.RecordSignInAsync(externalLoginId, cancellationToken);
        }
    }

    /// <summary>
    /// Also under the legacy validators, where the validated token is a JwtSecurityToken rather than a JsonWebToken; the provider token proves the call is wired at all.
    /// </summary>
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task A_local_token_is_never_sent_to_the_providers_userinfo_endpoint(bool legacyValidators)
    {
        using var identityProviderKey = RSA.Create(2048);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var userInfo = new UserInfoRecorder();

        await using var app = await StartAsync(
            identityProviderKey,
            localKey,
            services =>
            {
                services
                    .AddHttpClient(ToamaisutaaDefaults.UserInfoHttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => userInfo);

                services.PostConfigure<JwtBearerOptions>(
                    JwtBearerDefaults.AuthenticationScheme,
                    options => options.UseSecurityTokenValidators = legacyValidators);
            },
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
    /// With no API audience configured the accepted audience is the client id, which every ID token for that client also carries.
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
    /// Such an account has no password credential to hold the wrong-code count, yet must still lock.
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
        var confirmed = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, token);
        await Assert.That(confirmed.StatusCode).IsEqualTo(HttpStatusCode.OK);

        for (var i = 0; i < 5; i++)
        {
            app.Time.AdvanceToNextTotpStep();
            var wrong = Totp.WrongCode(secret, app.Time.Now);

            await app.Client.PostJson(path, new { proof = wrong }, token);
        }

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson(path, new { proof = Totp.Code(secret, app.Time.Now) }, token);

        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", token)).Json().Result.Bool("enabled")).IsTrue();
    }

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
        var confirmed = await app.Client.PostJson("/auth/2fa/confirm", new { code = Totp.Code(secret, app.Time.Now) }, token);
        await Assert.That(confirmed.StatusCode).IsEqualTo(HttpStatusCode.OK);

        app.Time.AdvanceToNextTotpStep();
        var wrong = Totp.WrongCode(secret, app.Time.Now);

        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            app.Client.PostJson("/auth/2fa/recovery-codes", new { proof = wrong }, token)));

        app.Time.AdvanceToNextTotpStep();
        var right = await app.Client.PostJson("/auth/2fa/recovery-codes", new { proof = Totp.Code(secret, app.Time.Now) }, token);

        // 400 also answers an account with nothing enrolled, so it only means locked if this holds.
        await Assert.That(right.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That((await app.Client.Get("/auth/2fa", token)).Json().Result.Bool("enabled")).IsTrue();
    }

    /// <summary>
    /// Keycloak before version 25 puts <c>nonce</c> into access tokens too, so the <c>typ</c> label must decide.
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

    /// <summary>Google's shape, which provisions a row with no user name and no password, the same shape as an invitation reservation.</summary>
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
