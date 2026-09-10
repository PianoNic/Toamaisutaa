using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The whole package behind a real HTTP pipeline, in process, on a throwaway database.
/// </summary>
/// <remarks>
/// <para>
/// This exists because three bugs shipped past a service suite that was correct throughout: a
/// rotated device token the endpoint dropped, endpoint names that made the routing matcher
/// unbuildable, and a security stamp exception that escaped as a 500. Every one of them lived
/// between a correct service and the wire, and nothing automated looked there.
/// </para>
/// <para>
/// No identity provider is needed. With <c>Oidc:Authority</c> unset the bearer handler never
/// attempts discovery and validates locally issued tokens against the configured signing key
/// alone, so the suite runs offline and deterministically.
/// </para>
/// </remarks>
internal sealed class TestApp : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly SqliteConnection _connection;

    private TestApp(
        WebApplication app,
        SqliteConnection connection,
        HttpClient client,
        MutableTimeProvider time,
        List<(Guid UserId, string Password)> issuedPasswords,
        List<(Guid UserId, string Token)> issuedInvitations,
        List<(Guid UserId, string Email, string Token)> issuedEmailVerifications,
        List<(Guid UserId, string Token)> issuedMagicLinks)
    {
        _app = app;
        _connection = connection;
        Client = client;
        Time = time;
        IssuedPasswords = issuedPasswords;
        IssuedInvitations = issuedInvitations;
        IssuedEmailVerifications = issuedEmailVerifications;
        IssuedMagicLinks = issuedMagicLinks;
    }

    /// <summary>Where the test host serves from, and so the only origin a WebAuthn ceremony here
    /// can claim. The browser puts this in the client data and the package checks it.</summary>
    public const string Origin = "http://localhost";

    /// <summary>What <c>Oidc:AdminRole</c> names here, which is what puts the admin provisioning
    /// endpoints on the wire and what their policy asks for.</summary>
    public const string AdminRole = "gate-master";

    /// <summary>
    /// The one account name <see cref="AdminRole"/> is granted to. Every other account this suite
    /// registers is an ordinary caller, which is what makes a 403 assertion mean something.
    /// </summary>
    public const string AdminUserName = "admin";

    public HttpClient Client { get; }

    /// <summary>The host's own container. For the few assertions that have to read what landed in
    /// the database rather than what came back in a body - a stored password hash is never on the
    /// wire, and that is the point of it.</summary>
    public IServiceProvider Services => _app.Services;

    /// <summary>
    /// What <c>IAdminPasswordIssuedNotifier</c> was handed - the only place a password an admin
    /// endpoint issued can be observed, since it is never in an HTTP response.
    /// </summary>
    public List<(Guid UserId, string Password)> IssuedPasswords { get; }

    /// <summary>What <c>IInvitationNotifier</c> was handed - the only place an invitation token can
    /// be observed, since it is never in an HTTP response.</summary>
    public List<(Guid UserId, string Token)> IssuedInvitations { get; }

    /// <summary>What <c>IEmailVerificationNotifier</c> was handed. The address is kept alongside the
    /// token, because which mailbox the link went to is the half of that flow that matters.</summary>
    public List<(Guid UserId, string Email, string Token)> IssuedEmailVerifications { get; }

    /// <summary>What <c>IMagicLinkNotifier</c> was handed. The only place a sign-in link can be
    /// observed, since it is never in an HTTP response.</summary>
    public List<(Guid UserId, string Token)> IssuedMagicLinks { get; }

    /// <summary>
    /// Advance it to cross a TOTP step. Anchored at the real clock and never moved far, because the
    /// bearer handler validates lifetimes against the system clock rather than this.
    /// </summary>
    public MutableTimeProvider Time { get; }

    /// <param name="mapExtra">Maps further endpoints, for tests about where endpoints land.</param>
    /// <param name="configure">Adjusts configuration before the host is built.</param>
    /// <param name="handleStaleStampGlobally">
    /// Registers the <c>IExceptionHandler</c> the docs hand a consumer. <b>Off by default, and that
    /// matters:</b> it turns a stale stamp into the same 401 the package's own endpoint filter
    /// produces, so leaving it on made every stale-stamp assertion below pass with the filter
    /// deleted. Mutation-tested, and it was masking the thing it was meant to check.
    /// </param>
    /// <param name="configureServices">Overrides a registration after the package's own - e.g.
    /// swapping in a notifier that throws, to prove a dependency failing does not become a 500.</param>
    /// <param name="includeAdminPasswordNotifier">
    /// On by default, so <c>/auth/users</c> and <c>/auth/users/{userId}/password</c> are mapped and
    /// most tests can use them. Off to prove they are not mapped at all without one.
    /// </param>
    /// <param name="includeInvitationNotifier">
    /// On by default, so <c>/auth/invitations</c> and <c>/auth/invitations/complete</c> are mapped
    /// and most tests can use them. Off to prove they are not mapped at all without one.
    /// </param>
    /// <param name="includeEmailVerificationNotifier">
    /// On by default, so <c>/auth/email</c> and <c>/auth/email/verify</c> are mapped and most tests
    /// can use them. Off to prove they are not mapped at all without one.
    /// </param>
    /// <param name="includeMagicLinkNotifier">
    /// Follows <paramref name="includeEmailVerificationNotifier"/> unless it is given, so
    /// <c>/auth/magic-link</c> and <c>/auth/magic-link/verify</c> are mapped for most tests. It has
    /// to follow rather than default to true: startup refuses a magic-link notifier with no way to
    /// verify an address, because then no address could ever qualify for a link. Pass false to prove
    /// the endpoints are not mapped at all without one.
    /// </param>
    /// <param name="remoteIpAddress">
    /// Puts an address on every connection. The test host leaves <c>RemoteIpAddress</c> null, so
    /// without this the columns fed from it are null throughout and a test about
    /// <c>IpAddressStorage</c> would pass whether the setting were honoured or ignored.
    /// </param>
    /// <param name="includeOpenApi">
    /// Adds <c>AddToamaisutaaOpenApi</c> and maps <c>/openapi/v1.json</c>. Off by default: it is a
    /// document generator no other test needs, and it makes the discovery fetch resolve back into
    /// this same host.
    /// </param>
    /// <param name="includeAdminRole">
    /// On by default: sets <c>Oidc:AdminRole</c> and grants it to <see cref="AdminUserName"/>, so
    /// the admin provisioning endpoints are mapped and one account can reach them. Off to prove
    /// they are not mapped at all when nothing says who an administrator is.
    /// </param>
    public static async Task<TestApp> StartAsync(
        Action<IEndpointRouteBuilder>? mapExtra = null,
        Action<Dictionary<string, string?>>? configure = null,
        bool handleStaleStampGlobally = false,
        Action<IServiceCollection>? configureServices = null,
        bool includeAdminPasswordNotifier = true,
        bool includeInvitationNotifier = true,
        bool includeEmailVerificationNotifier = true,
        bool? includeMagicLinkNotifier = null,
        string? remoteIpAddress = null,
        bool includeOpenApi = false,
        bool includeAdminRole = true)
    {
        var settings = new Dictionary<string, string?>
        {
            // No Authority: nothing to discover, nothing to reach over the network.
            ["Oidc:ClientId"] = "toamaisutaa-tests",
            ["Oidc:AdminRole"] = includeAdminRole ? AdminRole : null,
            ["LocalLogin:SigningKey"] = Convert.ToBase64String(new byte[32]),
            ["LocalLogin:Issuer"] = "toamaisutaa-tests",
            ["LocalLogin:AllowSelfRegistration"] = "true",
            // The limiter is per caller address and every request here comes from the same one.
            ["LocalLogin:RateLimit:Enabled"] = "false",
            ["TwoFactor:EncryptionKey"] = Convert.ToBase64String(new byte[32]),
            ["TrustedDevices:IpAddressStorage"] = "Truncated",
            ["LocalLogin:IpAddressStorage"] = "Truncated",
            // The test host serves everything from http://localhost, so that is the only origin a
            // ceremony can honestly claim to have happened on.
            ["Passkeys:RelyingPartyId"] = "localhost",
            ["Passkeys:Origins:0"] = Origin,
        };

        configure?.Invoke(settings);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(settings);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);

        var time = new MutableTimeProvider(DateTimeOffset.UtcNow);

        // Before AddToamaisutaaBearer, which registers TimeProvider.System with TryAdd.
        builder.Services.AddSingleton<TimeProvider>(time);

        var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        builder.Services.AddToamaisutaaBearer(builder.Configuration);
        builder.Services.AddToamaisutaaAuthorization(builder.Configuration);
        builder.Services.AddToamaisutaaProvisioning();
        builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(connection));
        builder.Services.AddToamaisutaaCurrentUser();
        builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
        builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);
        builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);
        builder.Services.AddToamaisutaaPasskeys(builder.Configuration);
        builder.Services.AddSingleton<IPasswordResetNotifier, SilentResetNotifier>();

        // This package ships no roles table, so a locally issued token carries no role until an
        // application supplies one. Stands in for that table, and grants the role to one name only.
        if (includeAdminRole)
            builder.Services.AddSingleton<IUserRoleProvider>(new AdminByNameRoleProvider());

        var issuedPasswords = new List<(Guid UserId, string Password)>();
        var issuedInvitations = new List<(Guid UserId, string Token)>();
        var issuedEmailVerifications = new List<(Guid UserId, string Email, string Token)>();
        var issuedMagicLinks = new List<(Guid UserId, string Token)>();

        if (includeAdminPasswordNotifier)
            builder.Services.AddSingleton<IAdminPasswordIssuedNotifier>(new CapturingAdminPasswordIssuedNotifier(issuedPasswords));

        if (includeInvitationNotifier)
            builder.Services.AddSingleton<IInvitationNotifier>(new CapturingInvitationNotifier(issuedInvitations));

        if (includeEmailVerificationNotifier)
            builder.Services.AddSingleton<IEmailVerificationNotifier>(new CapturingEmailVerificationNotifier(issuedEmailVerifications));

        if (includeMagicLinkNotifier ?? includeEmailVerificationNotifier)
            builder.Services.AddSingleton<IMagicLinkNotifier>(new CapturingMagicLinkNotifier(issuedMagicLinks));

        if (includeOpenApi)
        {
            builder.Services.AddToamaisutaaOpenApi(builder.Configuration);

            // Sends the discovery fetch back into this host instead of onto the network, so a test
            // serves its own issuer metadata from a route and the suite still needs no identity
            // provider. An address this host has no route for answers a refusal rather than a
            // document, which is the same "could not be read" branch as an issuer that is not
            // there at all.
            builder.Services
                .AddHttpClient(ToamaisutaaDefaults.DiscoveryHttpClientName)
                .ConfigurePrimaryHttpMessageHandler(services => ((TestServer)services.GetRequiredService<IServer>()).CreateHandler());
        }

        configureServices?.Invoke(builder.Services);

        if (handleStaleStampGlobally)
        {
            builder.Services.AddExceptionHandler<StaleSecurityStampHandler>();
            builder.Services.AddProblemDetails();
        }

        var app = builder.Build();

        if (handleStaleStampGlobally)
            app.UseExceptionHandler();

        if (remoteIpAddress is not null)
        {
            app.Use((context, next) =>
            {
                context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(remoteIpAddress);
                return next(context);
            });
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapToamaisutaaConfiguration();
        app.MapToamaisutaaPasswordEndpoints();
        app.MapToamaisutaaTwoFactorEndpoints();
        app.MapToamaisutaaTrustedDeviceEndpoints();
        app.MapToamaisutaaSessionEndpoints();
        app.MapToamaisutaaPasskeyEndpoints();

        // Stands in for an ordinary protected endpoint of the application's own.
        app.MapGet("/test/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
        {
            var user = await currentUser.GetOrProvisionAsync(cancellationToken);
            return Results.Ok(new { user.Id, user.UserName });
        });

        if (includeOpenApi)
            app.MapOpenApi().AllowAnonymous();

        mapExtra?.Invoke(app);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.EnsureCreatedAsync();
        }

        await app.StartAsync();

        return new TestApp(
            app,
            connection,
            app.GetTestClient(),
            time,
            issuedPasswords,
            issuedInvitations,
            issuedEmailVerifications,
            issuedMagicLinks);
    }

    /// <summary>
    /// A valid token for this host that carries no <c>toa_sid</c> - the shape an identity
    /// provider's token has, and the one step-up has to refuse with 400 rather than 401.
    /// </summary>
    /// <remarks>
    /// Minted rather than doctored. Editing a real token breaks its signature, so the request would
    /// be refused by the bearer pipeline and never reach the endpoint under test - a test that
    /// passes for the wrong reason.
    /// </remarks>
    public string MintTokenWithoutSession(string subject)
    {
        var key = new SymmetricSecurityKey(new byte[32]) { KeyId = ToamaisutaaDefaults.LocalSigningKeyId };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "toamaisutaa-tests",
            Audience = "toamaisutaa-tests",
            Subject = new ClaimsIdentity([new Claim("sub", subject)]),
            IssuedAt = Time.Now.UtcDateTime,
            NotBefore = Time.Now.UtcDateTime,
            Expires = Time.Now.AddMinutes(15).UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        });
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        await _connection.DisposeAsync();
    }

    /// <summary>Grants <see cref="AdminRole"/> to <see cref="AdminUserName"/> and to nobody
    /// else.</summary>
    private sealed class AdminByNameRoleProvider : IUserRoleProvider
    {
        public Task<IReadOnlyList<string>> GetRolesAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<string>>(user.UserName == AdminUserName ? [AdminRole] : []);
    }

    private sealed class SilentResetNotifier : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class CapturingAdminPasswordIssuedNotifier(List<(Guid UserId, string Password)> issued) : IAdminPasswordIssuedNotifier
    {
        public Task PasswordIssuedAsync(ToamaisutaaUser user, string rawPassword, CancellationToken cancellationToken = default)
        {
            issued.Add((user.Id, rawPassword));
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingInvitationNotifier(List<(Guid UserId, string Token)> sent) : IInvitationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default)
        {
            sent.Add((user.Id, invitationToken));
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingEmailVerificationNotifier(List<(Guid UserId, string Email, string Token)> sent) : IEmailVerificationNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default)
        {
            sent.Add((user.Id, email, verificationToken));
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingMagicLinkNotifier(List<(Guid UserId, string Token)> sent) : IMagicLinkNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default)
        {
            sent.Add((user.Id, magicLinkToken));
            return Task.CompletedTask;
        }
    }

    /// <summary>The handler the docs hand a consumer, verbatim, so the suite exercises it too.</summary>
    private sealed class StaleSecurityStampHandler : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(
            HttpContext context,
            Exception exception,
            CancellationToken cancellationToken)
        {
            if (exception is not SecurityStampChangedException)
                return false;

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";

            await context.Response.WriteAsJsonAsync(
                new ErrorResponse { Error = "invalid_token", ErrorDescription = exception.Message },
                cancellationToken);

            return true;
        }
    }
}

internal sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; private set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now = Now.Add(by);

    /// <summary>
    /// Moves to the next TOTP step. A code is accepted only if its step is strictly newer than the
    /// last accepted one, so two codes in a row need this between them.
    /// </summary>
    public void AdvanceToNextTotpStep()
    {
        var period = TimeSpan.FromSeconds(30);
        var elapsed = TimeSpan.FromTicks(Now.UtcTicks % period.Ticks);
        Advance(period - elapsed + TimeSpan.FromSeconds(1));
    }
}
