using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Validate access tokens against the issuer in the "Oidc" section. The authorization-code flow with
// PKCE belongs to the client; this is the resource-server half of it.
builder.Services.AddToamaisutaaBearer(builder.Configuration);

// Authenticated by default, plus the "Toamaisutaa.Admin" policy because Oidc:AdminRole is set.
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

// Everything below is optional: without it the API still authenticates, it just has no local user
// row. Three of the four applications this package was extracted from stop at the two calls above.
builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(
    builder.Configuration.GetConnectionString("Toamaisutaa") ?? "Data Source=toamaisutaa-sample.db",
    // Migrations are provider-specific, so the assembly holding them is named here rather than
    // guessed. Swap in the Postgres one and nothing else changes.
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
builder.Services.AddToamaisutaaCurrentUser();

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

if (app.Environment.IsDevelopment())
    app.MapOpenApi().AllowAnonymous();

app.MapGet("/api/public", () => "No token needed here.")
    .AllowAnonymous()
    .WithName("Public");

// The fallback policy covers this: no token, no answer.
app.MapGet("/api/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
{
    // First call for this subject creates the user row and its external login. Later calls read it,
    // and write nothing unless a claim actually changed.
    var user = await currentUser.GetOrProvisionAsync(cancellationToken);

    return Results.Ok(new
    {
        Local = new { user.Id, user.UserName, user.DisplayName, user.Email, user.PictureUrl, user.CreatedAt, user.UpdatedAt },
        FromToken = new { currentUser.Subject, Actor = currentUser.Name },
    });
})
.WithName("Me");

// Named policy from Oidc:AdminRole. A token without that role gets a 403 whose log line says which
// claim was read and what the token carried there.
app.MapGet("/api/admin", () => "You carry the admin role.")
    .RequireAuthorization("Toamaisutaa.Admin")
    .WithName("Admin");

app.Run();
