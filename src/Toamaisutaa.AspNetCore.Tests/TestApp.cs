using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
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

    private TestApp(WebApplication app, SqliteConnection connection, HttpClient client, MutableTimeProvider time)
    {
        _app = app;
        _connection = connection;
        Client = client;
        Time = time;
    }

    public HttpClient Client { get; }

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
    public static async Task<TestApp> StartAsync(
        Action<IEndpointRouteBuilder>? mapExtra = null,
        Action<Dictionary<string, string?>>? configure = null,
        bool handleStaleStampGlobally = false)
    {
        var settings = new Dictionary<string, string?>
        {
            // No Authority: nothing to discover, nothing to reach over the network.
            ["Oidc:ClientId"] = "toamaisutaa-tests",
            ["LocalLogin:SigningKey"] = Convert.ToBase64String(new byte[32]),
            ["LocalLogin:Issuer"] = "toamaisutaa-tests",
            ["LocalLogin:AllowSelfRegistration"] = "true",
            // The limiter is per caller address and every request here comes from the same one.
            ["LocalLogin:RateLimit:Enabled"] = "false",
            ["TwoFactor:EncryptionKey"] = Convert.ToBase64String(new byte[32]),
            ["TrustedDevices:IpAddressStorage"] = "Truncated",
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
        builder.Services.AddSingleton<IPasswordResetNotifier, SilentResetNotifier>();

        if (handleStaleStampGlobally)
        {
            builder.Services.AddExceptionHandler<StaleSecurityStampHandler>();
            builder.Services.AddProblemDetails();
        }

        var app = builder.Build();

        if (handleStaleStampGlobally)
            app.UseExceptionHandler();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapToamaisutaaConfiguration();
        app.MapToamaisutaaPasswordEndpoints();
        app.MapToamaisutaaTwoFactorEndpoints();
        app.MapToamaisutaaTrustedDeviceEndpoints();

        // Stands in for an ordinary protected endpoint of the application's own.
        app.MapGet("/test/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
        {
            var user = await currentUser.GetOrProvisionAsync(cancellationToken);
            return Results.Ok(new { user.Id, user.UserName });
        });

        mapExtra?.Invoke(app);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.EnsureCreatedAsync();
        }

        await app.StartAsync();

        return new TestApp(app, connection, app.GetTestClient(), time);
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

    private sealed class SilentResetNotifier : IPasswordResetNotifier
    {
        public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
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
