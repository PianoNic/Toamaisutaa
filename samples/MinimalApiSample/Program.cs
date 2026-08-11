using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Validate access tokens. Both the identity provider's and the ones this application issues itself:
// one handler, one scheme, and nothing downstream can tell which kind it is holding.
builder.Services.AddToamaisutaaBearer(builder.Configuration);

// Authenticated by default, plus the "Toamaisutaa.Admin" policy because Oidc:AdminRole is set.
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(
    builder.Configuration.GetConnectionString("Toamaisutaa") ?? "Data Source=toamaisutaa-sample.db",
    // Migrations are provider-specific, so the assembly holding them is named here rather than
    // guessed. Swap in the Postgres one and nothing else changes.
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
builder.Services.AddToamaisutaaCurrentUser();

// Local username and password sign-in. OIDC is the recommended path; this is the fallback for a
// deployment that cannot run an identity provider.
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
builder.Services.AddToamaisutaaTokenCleanup();

// Required, and deliberately not shipped: sending mail is not an authentication library's job. This
// one writes the link to the log, which is all a sample needs.
builder.Services.AddSingleton<IPasswordResetNotifier, LoggingPasswordResetNotifier>();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.MigrateAsync();
}

app.UseAuthentication();
app.UseAuthorization();

// What the SPA reads at startup to configure its OIDC client. Anonymous, since it is needed before
// anyone has signed in.
app.MapToamaisutaaConfiguration();

// POST /auth/login, /auth/refresh, /auth/logout, /auth/register, /auth/password,
// /auth/password/forgot, /auth/password/reset.
app.MapToamaisutaaPasswordEndpoints();

if (app.Environment.IsDevelopment())
    app.MapOpenApi().AllowAnonymous();

app.MapGet("/api/public", () => "The gate stands open here. No token needed.")
    .AllowAnonymous()
    .WithName("Public");

// The fallback policy covers this: no token, no answer. It does not care whether the token came
// from the identity provider or from /auth/login.
app.MapGet("/api/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
{
    var user = await currentUser.GetOrProvisionAsync(cancellationToken);

    return Results.Ok(new
    {
        Local = new { user.Id, user.UserName, user.DisplayName, user.Email, user.CreatedAt, user.UpdatedAt },
        FromToken = new { currentUser.Subject, Actor = currentUser.Name },
    });
})
.WithName("Me");

// Named policy from Oidc:AdminRole. Local accounts carry no roles until an IUserRoleProvider says
// otherwise, so a locally issued token gets a 403 here - by design, and documented.
app.MapGet("/api/admin", () => "The gate master knows you. Come through.")
    .RequireAuthorization("Toamaisutaa.Admin")
    .WithName("Admin");

app.Run();

/// <summary>
/// Stands in for whatever the application already uses to send mail. The token is the only thing
/// here that matters, so it stays on its own and unadorned - paste it into /auth/password/reset.
/// </summary>
internal sealed class LoggingPasswordResetNotifier(ILogger<LoggingPasswordResetNotifier> logger) : IPasswordResetNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("No postman in this sample, so the gate master reads it aloud.");
        logger.LogWarning("PASSWORD RESET for {Email}: token {Token}", user.Email, resetToken);
        return Task.CompletedTask;
    }
}
