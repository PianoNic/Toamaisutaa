# Getting started

Password login with two-factor authentication, on SQLite, in one `Program.cs`. Everything else -
an identity provider, passkeys, another database - is a step on from this, linked at the end.

Needs **.NET 10**.

## Quick start

```sh
dotnet new web -n MyApp && cd MyApp
dotnet add package Toamaisutaa.AspNetCore
dotnet add package Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite
```

Two keys, one to sign tokens and one to encrypt the two-factor secrets. Generate each:

```sh
openssl rand -base64 32
# or, in PowerShell: [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

`appsettings.json`:

```json
{
  "LocalLogin": {
    "SigningKey": "<first key>",
    "Audience": "my-app"
  },
  "TwoFactor": {
    "EncryptionKey": "<second key>"
  }
}
```

`appsettings.Development.json` - open registration on your machine only, so there is an account to
try things with:

```json
{
  "LocalLogin": {
    "AllowSelfRegistration": true
  }
}
```

`Program.cs`:

```csharp
using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);
builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite("Data Source=app.db",
    sqlite => sqlite.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite")));
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);

// Prints links to the console, which is fine on your machine and nowhere else: anyone who can read
// the logs could take over any account. Startup refuses it outside Development.
if (!builder.Environment.IsDevelopment())
    throw new InvalidOperationException("ConsoleMail prints reset and verification links to the console. Register real mail first.");

builder.Services.AddSingleton<ConsoleMail>();
builder.Services.AddSingleton<IPasswordResetNotifier>(services => services.GetRequiredService<ConsoleMail>());
builder.Services.AddSingleton<IEmailVerificationNotifier>(services => services.GetRequiredService<ConsoleMail>());

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().Database.Migrate();

app.UseAuthentication();
app.UseAuthorization();

app.MapToamaisutaaPasswordEndpoints();
app.MapToamaisutaaTwoFactorEndpoints();

app.MapGet("/hello", () => "Signed in.");

app.Run();

// Replace with real mail before anyone else uses this.
sealed class ConsoleMail : IPasswordResetNotifier, IEmailVerificationNotifier
{
    public Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default)
    {
        Console.WriteLine($"Reset token for {user.Email}: {resetToken}");
        return Task.CompletedTask;
    }

    public Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default)
    {
        Console.WriteLine($"Verification token for {email}: {verificationToken}");
        return Task.CompletedTask;
    }
}
```

`dotnet run`. Every endpoint now needs a token unless it says `.AllowAnonymous()`, and a missing key
or setting stops startup with a message naming it rather than failing at the first request.

A password reset goes only to an address that has been verified, which is why a verification
notifier is registered even this early: without one, startup refuses, because no reset could ever
be sent.

## Try it

1. **Register** - `POST /auth/register` with `{ "userName": "ada", "email": "ada@example.com",
   "password": "correct horse battery staple" }`. Answers `201` with an `access_token`. Run in
   Development (`dotnet run` is, by default), since registration is only open there.
2. **Call your endpoint** - `GET /hello` with `Authorization: Bearer <access_token>`. `200`; without
   the header, `401`.
3. **Turn on two-factor** - `POST /auth/2fa/begin` with `{ "currentPassword": "..." }` and the token.
   Scan the returned `uri` (or type the `secret`) into an authenticator app, then `POST
   /auth/2fa/confirm` with `{ "code": "123456" }`. Answers the recovery codes, once.
4. **Sign in** - `POST /auth/login` with `{ "identifier": "ada", "password": "..." }` now answers
   `two_factor_required: true` and a `challenge` instead of tokens. `POST /auth/2fa/verify` with
   `{ "challenge": "...", "code": "123456" }` answers the tokens.

Refresh with `POST /auth/refresh` and `{ "refreshToken": "..." }`, sign out with `POST /auth/logout`.
Every route and body: [local password login](/password-login).

## Before it goes public

- **Keys from the environment**, never committed: `LocalLogin__SigningKey`, `TwoFactor__EncryptionKey`.
  The sample's published keys are refused outside Development. [Signing local tokens](/token-signing)
  covers rotating keys and asymmetric signing.
- **Real mail** for password resets and address verification: your own notifiers, or the SMTP
  package - [provisioning accounts](/provisioning-accounts). The console one above refuses to start
  outside Development, because anyone reading the logs could take over any account.
- **Behind a reverse proxy**, forward the client's address, or every caller shares one rate limit -
  [behind a proxy](/password-login#behind-a-proxy-configure-forwarded-headers).
- **Decide who may register.** It is on in Development only. Turned on everywhere, anyone can create
  an account and call every endpoint that only asks for a signed-in user, and registration answers
  409 for a taken name, which tells a stranger who has an account. Without it, accounts come from an
  admin or an invitation - [provisioning accounts](/provisioning-accounts).
- **A production database** - [storage and migrations](/storage).

## Next steps

| To add | Read |
|---|---|
| Sign-in through Keycloak, Entra, Authentik or another OIDC provider | [OIDC bearer validation](/oidc) |
| Postgres, SQL Server, MySQL, or your own `DbContext` | [Storage and migrations](/storage) |
| A browser front end: the sign-in branch, refresh, where tokens live | [Using this from a SPA](/spa) |
| Passkeys | [Passkeys](/passkeys) |
| "Remember this device" for the second factor | [Trusted devices](/trusted-devices) |
| Sign-in by emailed link | [Magic-link sign-in](/magic-link), which needs [email verification](/email-verification) |
| Admin-created accounts and invitations | [Provisioning accounts](/provisioning-accounts) |
| A list of a user's sessions, and signing out elsewhere | [Sessions](/sessions) |
| Roles for local accounts, and other hooks | [Customizing local login](/customizing-password-login) |
| Who is calling, from a service | [The current user](/current-user) |
| Argon2id, or a breached-password check | [Password hashing](/password-hashing), [breached passwords](/breached-passwords) |
| An audit trail, or metrics | [Audit events](/audit-events), [metrics](/metrics) |
| These endpoints in your OpenAPI document | [OpenAPI](/openapi) |

## With an identity provider instead

A resource server whose users all come from an OIDC provider needs no database and no keys of its
own:

```sh
dotnet add package Toamaisutaa.AspNetCore
```

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
```

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

Both together work too: local password login next to the provider, each validated by the same
pipeline. [OIDC bearer validation](/oidc) has every key.

## The sample

`samples/MinimalApiSample` in the repository wires nearly everything at once against a throwaway
identity provider: password login, two-factor, passkeys, trusted devices, magic links, sessions,
OpenAPI. Four lines of Docker and a `dotnet run`.
