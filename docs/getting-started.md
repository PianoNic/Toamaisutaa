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

## Roles and claims without `HttpContext`

`ICurrentUser` also reports what the token says about the caller, so code that is not an endpoint
can answer "is this an admin" without reaching for `HttpContext` - which is the thing the interface
exists to avoid:

```csharp
public sealed class ArchiveService(ICurrentUser currentUser)
{
    public Task PurgeAsync()
    {
        if (!currentUser.IsInRole("archivist"))
            throw new UnauthorizedAccessException();

        var tenant = currentUser.FindClaim("tenant_id");
        ...
    }
}
```

- **`Roles`** reads the claim `Oidc:RoleClaim` names - `roles` by default, `groups` on Pocket ID,
  Authentik and Entra - and falls back to .NET's own role claim type for a principal that did not
  come from this package's bearer pipeline. Empty on an anonymous request, and empty for a locally
  issued token until an
  [`IUserRoleProvider`](/customizing-password-login#local-accounts-have-no-roles) supplies some.
- **`IsInRole`** compares ordinally, the same comparison `RequireRole` makes.
- **`FindClaim`** takes a raw JWT claim type - `tenant_id`, not the WS-Federation URI - because
  inbound claim mapping is off. It returns the first non-empty value.

This is a read of the token, not an authorization decision. It answers "what does this caller
carry"; `[Authorize]` answers "may this caller in", and a check that only happens inside a service
is one an unprotected route still skips.

The whole set is available on a project that references only `Toamaisutaa.Abstractions`. An
implementation of your own - a worker, a test double - inherits an empty answer for all three and
only overrides what it can actually answer.

## The runtime configuration endpoint

`MapToamaisutaaConfiguration()` serves the authority, client id, scope and redirect URIs at
`/api/app` so a SPA build stays environment-agnostic. It is anonymous, because it is needed before
anyone has signed in.

```json
{
  "authority": "https://id.example.com",
  "clientId": "your-app",
  "redirectUri": "https://app.example.com/",
  "postLogoutRedirectUri": "https://app.example.com/",
  "scope": "openid profile email roles"
}
```

The route is a parameter: `MapToamaisutaaConfiguration("/api/config")`. This is an application
configuration endpoint rather than an auth one, so it is the likeliest of these to collide with
conventions you already have.

To serve **your own fields alongside these, or from a route of your own**, skip the map call and
inject `IToamaisutaaClientConfigurationProvider` into an endpoint you write:

```csharp
app.MapGet("/api/app", (HttpContext context, IToamaisutaaClientConfigurationProvider provider) =>
    Results.Ok(new
    {
        Auth = provider.GetConfiguration(context),
        FeatureFlags = /* whatever else your SPA reads at startup */
    }))
    .AllowAnonymous();
```

The redirect-URI resolution, which is the only part with real logic in it, stays in one place either
way.

## Adding these endpoints to your OpenAPI document

Every endpoint this package maps describes itself: response types, status codes, summaries, and a
tag per group. They appear in a generated document with no work from you.

**The security schemes are one call.** A security scheme is a document-level declaration, so
somebody has to add it: without one, nothing marks which endpoints need a token and Scalar or
Swagger UI shows no Authorize box, which is how most people first try an API.

```sh
dotnet add package Toamaisutaa.OpenApi
```

```csharp
builder.Services.AddToamaisutaaOpenApi(builder.Configuration);   // section "Oidc"

app.MapOpenApi().AllowAnonymous();
```

That puts four things in the document:

- a **`Bearer`** HTTP scheme, for a token pasted in from `/auth/login` or `/auth/2fa/verify`;
- an **`OAuth2`** authorization-code scheme, with the authorization and token URLs read from your
  issuer's discovery document and the scopes from `Oidc:Scope`;
- the **requirement, document-wide**, naming both schemes as alternatives - either token gets in;
- **no padlock on anonymous endpoints**. `/auth/login` is the endpoint you call because you have no
  token yet.

Its own package, because `Microsoft.AspNetCore.OpenApi` is not part of the shared framework and an
application documenting itself some other way should not pay for it.

If your issuer cannot be reached while the document is generated, the `OAuth2` scheme is left out,
the rest of the document is unchanged, and one warning line says which address failed. With no
`Oidc:Authority` configured at all there is no authorization server to describe, and the `Bearer`
scheme stands alone - which is exactly right for a deployment that only issues its own tokens.

To render it, `Scalar.AspNetCore` is one line:

```csharp
app.MapScalarApiReference().AllowAnonymous();   // /scalar
```

`samples/MinimalApiSample` has both, wired exactly as above.

### With transformers of your own

`AddOpenApi` called twice for the same document registers everything twice, so pass your own
configuration through instead:

```csharp
builder.Services.AddToamaisutaaOpenApi(
    builder.Configuration,
    configureOptions: options => options.AddDocumentTransformer(YourOwnTransformer));
```

Or, where the document is already yours, add the schemes to it:

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddToamaisutaaSecuritySchemes();
    // ... whatever else you already had
});
```

## Endpoints of yours that resolve the current user

`ICurrentUser.GetOrProvisionAsync` throws `SecurityStampChangedException` when the token was issued
before a credential on the account changed - a password change, a two-factor enrolment. The token is
genuinely stale even though its signature and expiry are fine, and the client only needs to refresh.

Toamaisutaa's own endpoints answer 401 for this. **Endpoints you write need to as well**, or it
surfaces as a 500 for something that is an ordinary authentication failure:

```csharp
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
```

```csharp
builder.Services.AddExceptionHandler<StaleSecurityStampHandler>();
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
```

## The sample

`samples/MinimalApiSample` in the repository runs the whole thing against a throwaway identity
provider: an anonymous endpoint, a provisioning endpoint, an admin-only endpoint, one behind the
two-factor policy, the configuration endpoint, and the local sign-in and two-factor endpoints. Four
lines of Docker and a `dotnet run`.
