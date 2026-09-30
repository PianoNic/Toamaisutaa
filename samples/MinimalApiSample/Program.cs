using System.Diagnostics.Metrics;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Security schemes are document-level, so without this an API explorer offers no Authorize box.
builder.Services.AddToamaisutaaOpenApi(builder.Configuration);

builder.Services.AddToamaisutaaBearer(builder.Configuration);

builder.Services.AddToamaisutaaHealthChecks();

builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(
    builder.Configuration.GetConnectionString("Toamaisutaa") ?? "Data Source=toamaisutaa-sample.db",
    // Migrations are provider-specific, so the assembly holding them has to be named.
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
builder.Services.AddToamaisutaaCurrentUser();

builder.Services.AddToamaisutaaArgon2PasswordHashing(builder.Configuration);

builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);

builder.Services.AddToamaisutaaHibpPasswordValidation(builder.Configuration);

builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);

builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);

// The relying party is localhost only because that is where this sample is served from.
builder.Services.AddToamaisutaaPasskeys(builder.Configuration);

builder.Services.AddToamaisutaaTokenCleanup();

builder.Services.AddHostedService<MetricsToTheLog>();

// Two minutes so the sample is quick to try; five is a saner default.
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("FreshSecondFactor", policy => policy
        .RequireAuthenticatedUser()
        .RequireFreshSecondFactor(TimeSpan.FromMinutes(2)));

// Required, and not shipped: the package sends no mail, so the application supplies a sender.
builder.Services.AddSingleton<IPasswordResetNotifier, LoggingPasswordResetNotifier>();

builder.Services.AddToamaisutaaAuthenticationEventSink<LoggingAuditSink>();

// Optional: registering it is what puts /auth/email and /auth/email/verify on the wire.
builder.Services.AddSingleton<IEmailVerificationNotifier, LoggingEmailVerificationNotifier>();

// This token is the session itself. Registering it puts /auth/magic-link on the wire, and startup
// refuses it without the email verification notifier above.
builder.Services.AddSingleton<IMagicLinkNotifier, LoggingMagicLinkNotifier>();

// Needed for your own endpoints: without it a stale security stamp from
// ICurrentUser.GetOrProvisionAsync surfaces as a 500 instead of a 401.
builder.Services.AddExceptionHandler<StaleSecurityStampHandler>();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();

await using (var scope = app.Services.CreateAsyncScope())
{
    await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.MigrateAsync();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapToamaisutaaConfiguration();

app.MapToamaisutaaPasswordEndpoints();

app.MapToamaisutaaTwoFactorEndpoints();

app.MapToamaisutaaTrustedDeviceEndpoints();

app.MapToamaisutaaSessionEndpoints();

app.MapToamaisutaaPasskeyEndpoints();

// Must be anonymous: the fallback policy would otherwise answer 401, which an orchestrator reads as
// a failing probe.
app.MapHealthChecks("/health").AllowAnonymous();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();

    app.MapScalarApiReference(options => options.WithTitle("Toamaisutaa sample")).AllowAnonymous();
}

app.MapGet("/api/public", () => "The gate stands open here. No token needed.")
    .AllowAnonymous()
    .WithName("Public");

app.MapGet("/api/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
{
    var user = await currentUser.GetOrProvisionAsync(cancellationToken);

    return Results.Ok(new
    {
        Local = new { user.Id, user.UserName, user.DisplayName, user.Email, user.CreatedAt, user.UpdatedAt },
        FromToken = new
        {
            currentUser.Subject,
            Actor = currentUser.Name,
            currentUser.Roles,
            IsGateMaster = currentUser.IsInRole("gate-master"),
            SecondFactor = currentUser.FindClaim(ToamaisutaaDefaults.TwoFactorSourceClaim),
        },
    });
})
.WithName("Me");

// Local accounts carry no roles until you register an IUserRoleProvider, so a locally issued token
// gets a 403 here.
app.MapGet("/api/admin", () => "The gate master knows you. Come through.")
    .RequireAuthorization("Toamaisutaa.Admin")
    .WithName("Admin");

app.MapGet("/api/sensitive", () => "Two locks, both opened. This is the inner room.")
    .RequireAuthorization("Toamaisutaa.TwoFactor")
    .WithName("Sensitive");

app.MapGet("/api/vault", () => "Nothing cached got you in here. That was a live code.")
    .RequireAuthorization("FreshSecondFactor")
    .WithName("Vault");

app.Run();

/// <summary>
/// Answers 401 <c>invalid_token</c> for a stale security stamp so clients refresh rather than treat
/// it as a server fault.
/// </summary>
internal sealed class StaleSecurityStampHandler : IExceptionHandler
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

/// <summary>
/// A stand-in for an exporter; a real deployment points OpenTelemetry at the same meter by name.
/// </summary>
internal sealed class MetricsToTheLog(ILogger<MetricsToTheLog> logger) : IHostedService
{
    private readonly MeterListener _listener = new();

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == ToamaisutaaDefaults.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };

        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Write(instrument, value, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Write(instrument, value, tags));
        _listener.Start();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _listener.Dispose();
        return Task.CompletedTask;
    }

    private void Write(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var described = new StringBuilder();

        foreach (var tag in tags)
            described.Append(described.Length == 0 ? " " : ", ").Append(tag.Key).Append('=').Append(tag.Value);

        logger.LogInformation("{Instrument} {Value}{Tags}", instrument.Name, value, described.ToString());
    }
}

internal sealed class LoggingAuditSink(ILogger<LoggingAuditSink> logger) : IAuthenticationEventSink
{
    public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
    {
        logger.LogInformation(
            "Audit: {Kind} for user {UserId} at {OccurredAt} [{Methods}].",
            authenticationEvent.Kind,
            authenticationEvent.UserId,
            authenticationEvent.OccurredAt,
            string.Join(' ', authenticationEvent.AuthenticationMethods));

        return Task.CompletedTask;
    }
}

internal sealed class LoggingPasswordResetNotifier(ILogger<LoggingPasswordResetNotifier> logger) : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("No postman in this sample, so the gate master reads it aloud.");
        logger.LogWarning("PASSWORD RESET for {Email}: token {Token}", user.Email, resetToken);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Send to <c>email</c>, the address being verified, not the account's current one.
/// </summary>
internal sealed class LoggingEmailVerificationNotifier(ILogger<LoggingEmailVerificationNotifier> logger) : IEmailVerificationNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("The gate master reads this one aloud too, at the door it was addressed to.");
        logger.LogWarning("EMAIL VERIFICATION for {Email}: token {Token}", email, verificationToken);
        return Task.CompletedTask;
    }
}

internal sealed class LoggingMagicLinkNotifier(ILogger<LoggingMagicLinkNotifier> logger) : IMagicLinkNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("This one the gate master would rather whisper. Nothing else here opens a door by itself.");
        logger.LogWarning("MAGIC LINK for {Email}: token {Token}", user.Email, magicLinkToken);
        return Task.CompletedTask;
    }
}
