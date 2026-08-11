# Toamaisutaa.AspNetCore

**Start here.** This is the package most applications install: authorization, `ICurrentUser`, and
every endpoint [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) maps. It depends on
`Toamaisutaa.OpenIdConnect`, so one install gets you token validation as well.

```bash
dotnet add package Toamaisutaa.AspNetCore
```

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaAuthorization(builder.Configuration);

app.UseAuthentication();
app.UseAuthorization();
app.MapToamaisutaaConfiguration();   // GET /api/app, for the SPA to read at startup
```

Requires **.NET 10**. That is the whole minimum - authenticated by default, `[AllowAnonymous]` to opt
out, and no database at all.

## What it adds

- **Authenticated by default**, with an optional admin role and policy. An application can also
  authenticate however it likes and use only the policies.
- **`ICurrentUser`** - the subject and display name from the token, and the local user row if you
  provision one.
- **`GET /api/app`** - the runtime OIDC configuration a SPA reads at startup, so the authority and
  client id live in one place rather than being baked into a bundle.

## Optional: local password login

For deployments that cannot run an identity provider. Off unless you ask for it.

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);   // section "LocalLogin"
builder.Services.AddSingleton<IPasswordResetNotifier, YourEmailSender>();

app.MapToamaisutaaPasswordEndpoints();
```

Maps `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/register`, `/auth/password`,
`/auth/password/forgot` and `/auth/password/reset`. The anonymous ones throttle themselves through a
rate limiter this package owns, so forgetting `UseRateLimiter()` cannot leave them unprotected.

You must supply an `IPasswordResetNotifier` - sending mail is not an authentication library's job,
and this one deliberately ships no implementation. That, a store registration and the bearer layer
are all checked at startup rather than at the first sign-in.

## Optional: two-factor authentication

```csharp
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);   // section "TwoFactor"

app.MapToamaisutaaTwoFactorEndpoints();
```

TOTP with recovery codes, and no new dependency. Once a user enrols, `/auth/login` returns an opaque
single-use challenge instead of tokens and the sign-in finishes at `/auth/2fa/verify`. Locally issued
tokens carry `amr` per RFC 8176, and a `Toamaisutaa.TwoFactor` policy is registered for routes that
should require a second factor.

## Why not ASP.NET Core Identity?

Because Identity assumes it owns the users, and this assumes your identity provider does. Identity
has no built-in OIDC support, its endpoints issue proprietary tokens rather than JWTs, and a local
user table is mandatory. Here all three are the other way round. Use Identity for a self-contained
application that owns its users - it ships with the framework and is better tested than this.

[The longer answer, with the comparison table](https://docs.toamaisutaa.pianonic.ch/intro#why-not-asp-net-core-identity).

## Optional: trusted devices

```csharp
builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);   // section "TrustedDevices"

app.MapToamaisutaaTrustedDeviceEndpoints();
```

"Remember this device", as a cached second factor: it rotates on every use with reuse detection, dies
with any credential change, and never stands in for the password. Tokens carry `toa_2fa_source` and
`toa_2fa_at`, so a sensitive route can require a *fresh* second factor rather than a cached one.

## Storage

The optional features need somewhere to put a user. Add `Toamaisutaa.EntityFrameworkCore` and one of
the four migration packages, or implement the store interfaces yourself.

## Documentation

**[Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
