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
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// With <c>Oidc:Authority</c> unset the bearer handler never attempts discovery and validates
/// locally issued tokens against the configured signing key alone, so the suite runs offline.
/// </summary>
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

    public const string Origin = "http://localhost";

    public const string AdminRole = "gate-master";

    /// <summary>
    /// The only account granted <see cref="AdminRole"/>, so a 403 for any other account means something.
    /// </summary>
    public const string AdminUserName = "admin";

    public HttpClient Client { get; }

    public const string RemoteIpHeader = "X-Test-Remote-Ip";

    /// <summary>Does not wait for queued mail, for the test that the response does not wait for it either.</summary>
    public HttpClient RawClient => _app.GetTestClient();

    public IServiceProvider Services => _app.Services;

    public List<(Guid UserId, string Password)> IssuedPasswords { get; }

    public List<(Guid UserId, string Token)> IssuedInvitations { get; }

    public List<(Guid UserId, string Email, string Token)> IssuedEmailVerifications { get; }

    public List<(Guid UserId, string Token)> IssuedMagicLinks { get; }

    /// <summary>
    /// Anchored at the real clock and never moved far, because the bearer handler validates
    /// lifetimes against the system clock rather than this.
    /// </summary>
    public MutableTimeProvider Time { get; }

    // handleStaleStampGlobally is off by default because the handler produces the same 401 as the
    // package's endpoint filter, so leaving it on lets every stale-stamp test pass with the filter deleted.
    // includeMagicLinkNotifier follows includeEmailVerificationNotifier rather than defaulting to true,
    // because startup refuses a magic-link notifier with no way to verify an address.
    // remoteIpAddress exists because the test host leaves RemoteIpAddress null, so without it a test
    // about IpAddressStorage would pass whether the setting were honoured or ignored.
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
            ["Oidc:ClientId"] = "toamaisutaa-tests",
            ["Oidc:AdminRole"] = includeAdminRole ? AdminRole : null,
            ["LocalLogin:SigningKey"] = Convert.ToBase64String(new byte[32]),
            ["LocalLogin:Issuer"] = "toamaisutaa-tests",
            ["LocalLogin:AllowSelfRegistration"] = "true",
            // The limiter is per caller address and every request here comes from the same one.
            ["LocalLogin:RateLimit:Enabled"] = "false",
            // Tests ask for links to the same address back to back. The cooldown has its own test.
            ["LocalLogin:MailRequestCooldown"] = "00:00:00",
            // A second per refused sign-in would make the suite crawl. The floor has its own test.
            ["LocalLogin:SignInRefusalFloor"] = "00:00:00",
            ["TwoFactor:EncryptionKey"] = Convert.ToBase64String(new byte[32]),
            ["TrustedDevices:IpAddressStorage"] = "Truncated",
            ["LocalLogin:IpAddressStorage"] = "Truncated",
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

        // A file rather than one shared in-memory connection, because one connection handed to every
        // scope is not thread-safe and parallel requests fail on it.
        var databasePath = Path.Combine(Path.GetTempPath(), $"toamaisutaa-tests-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString();

        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();

        // Without WAL, parallel requests fail with "database is locked" rather than waiting their turn.
        await using (var wal = connection.CreateCommand())
        {
            wal.CommandText = "PRAGMA journal_mode=WAL;";
            await wal.ExecuteNonQueryAsync();
        }

        builder.Services.AddToamaisutaaBearer(builder.Configuration);
        builder.Services.AddToamaisutaaAuthorization(builder.Configuration);
        builder.Services.AddToamaisutaaProvisioning();
        builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(connectionString));
        builder.Services.AddToamaisutaaCurrentUser();
        builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
        builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);
        builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);
        builder.Services.AddToamaisutaaPasskeys(builder.Configuration);
        builder.Services.AddSingleton<IPasswordResetNotifier, SilentResetNotifier>();

        // The package ships no roles table, so this stands in for the one an application supplies.
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

            // Sends the discovery fetch back into this host instead of onto the network, so the
            // suite still needs no identity provider.
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

        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(RemoteIpHeader, out var perRequest))
                context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(perRequest.ToString());
            else if (remoteIpAddress is not null)
                context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(remoteIpAddress);

            return next(context);
        });

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapToamaisutaaConfiguration();
        app.MapToamaisutaaPasswordEndpoints();
        app.MapToamaisutaaTwoFactorEndpoints();
        app.MapToamaisutaaTrustedDeviceEndpoints();
        app.MapToamaisutaaSessionEndpoints();
        app.MapToamaisutaaPasskeyEndpoints();

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

        var server = app.GetTestServer();
        var queue = app.Services.GetRequiredService<MailRequestQueue>();

        // Waits for queued mail after every response, so a test can read what a notifier was handed.
        var client = new HttpClient(new MailDrainingHandler(queue) { InnerHandler = server.CreateHandler() })
        {
            BaseAddress = server.BaseAddress,
        };

        return new TestApp(
            app,
            connection,
            client,
            time,
            issuedPasswords,
            issuedInvitations,
            issuedEmailVerifications,
            issuedMagicLinks);
    }

    /// <summary>
    /// Minted rather than doctored, because editing a real token breaks its signature and the
    /// request never reaches the endpoint under test.
    /// </summary>
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

        try
        {
            File.Delete(_connection.DataSource);
        }
        catch (IOException)
        {
            // A handle the runtime has not let go of yet. The temp directory takes it from here.
        }
    }

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

    /// <summary>The handler the docs hand a consumer, verbatim, so keep the two in step.</summary>
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
    /// A code is accepted only if its step is strictly newer than the last accepted one, so two codes
    /// in a row need this between them.
    /// </summary>
    public void AdvanceToNextTotpStep()
    {
        var period = TimeSpan.FromSeconds(30);
        var elapsed = TimeSpan.FromTicks(Now.UtcTicks % period.Ticks);
        Advance(period - elapsed + TimeSpan.FromSeconds(1));
    }
}

internal sealed class MailDrainingHandler(MailRequestQueue queue) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken);
        await queue.WhenIdleAsync();
        return response;
    }
}
