# Getting started

## Requirements

- **.NET 10.** Every package targets `net10.0` and nothing older.
- An OIDC provider, if you want the recommended path. Anything that publishes a discovery document
  works: Keycloak, Authentik, Pocket ID, Okta, Entra.

## Install

A resource server validating tokens from your identity provider:

```sh
dotnet add package Toamaisutaa.OpenIdConnect
dotnet add package Toamaisutaa.AspNetCore
```

Plus, if you want a local user row or local password login:

```sh
dotnet add package Toamaisutaa.EntityFrameworkCore
dotnet add package Toamaisutaa.EntityFrameworkCore.Migrations.Postgres   # or .Sqlite, .SqlServer, .MySql
```

`Toamaisutaa.Abstractions` and `Toamaisutaa.Core` arrive as dependencies. Reference `Abstractions`
directly from a domain project that wants `ICurrentUser` without ASP.NET.

## The minimum

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
app.MapToamaisutaaConfiguration();   // GET /api/app, for the SPA to read at startup
```

That authenticates every endpoint by default, opts individual ones out with `[AllowAnonymous]`, and
needs no database at all. For a resource server whose identity provider owns every user, that is the
whole integration.

Configuration lives under `Oidc`:

```json
{
  "Oidc": {
    "Authority": "https://id.example.com",
    "ClientId": "your-app",
    "RoleClaim": "roles",
    "AdminRole": "admin"
  }
}
```

See [OIDC bearer validation](/oidc) for every key.

## With a local user

Provisioning is opt-in. Add it when you want a row of your own to hang data off:

```csharp
builder.Services.AddToamaisutaaProvisioning();
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
builder.Services.AddToamaisutaaCurrentUser();
```

Then inject `ICurrentUser`:

```csharp
app.MapGet("/api/me", async (ICurrentUser currentUser, CancellationToken cancellationToken) =>
{
    var user = await currentUser.GetOrProvisionAsync(cancellationToken);
    return Results.Ok(new { user.Id, user.DisplayName, user.Email });
});
```

The row is created on the first request that ever carries that subject, and read - not rewritten -
on every request after. See [Storage and migrations](/storage).

## The runtime configuration endpoint

`MapToamaisutaaConfiguration()` serves the authority, client id, scope and redirect URIs at
`/api/app` so a SPA build stays environment-agnostic. It is anonymous, because it is needed before
anyone has signed in.

Applications that serve their own fields from the same route should inject
`IToamaisutaaClientConfigurationProvider` into their own endpoint instead - the redirect-URI
resolution, which is the only part with real logic in it, stays in one place either way.

## The sample

`samples/MinimalApiSample` in the repository runs the whole thing against a throwaway identity
provider: an anonymous endpoint, a provisioning endpoint, an admin-only endpoint, one behind the
two-factor policy, the configuration endpoint, and the local sign-in and two-factor endpoints. Four
lines of Docker and a `dotnet run`.
