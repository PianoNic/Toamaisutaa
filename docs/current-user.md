# The current user

`ICurrentUser` is who is calling, in code that is not an endpoint, and optionally a row of your own
for them.

## A local user row

For an identity provider's users, provisioning is opt-in; local login creates the row itself. Add it when you want a row of your own to hang data off:

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

- **`Roles`** reads both the claim `Oidc:RoleClaim` names - `roles` by default, `groups` on Pocket
  ID, Authentik and Entra - and the role claim type the principal's own identities name, which is the
  one `RequireRole` reads. So a role check in a service and one on a route answer alike. Empty on an
  anonymous request, and empty for a locally issued token until an
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
