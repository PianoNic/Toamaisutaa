<p align="center">
  <img src="assets/icon.svg" width="180" alt="Toamaisutaa Logo" />
</p>
<p align="center">
  <strong>Toamaisutaa</strong><br/>
  トアマイスター - "gate master". Who gets through the gate.
</p>
<p align="center">
  <a href="https://github.com/PianoNic/Toamaisutaa"><img src="https://badgetrack.pianonic.ch/badge?tag=toamaisutaa&label=visits&color=0d1117&style=flat" alt="visits" /></a>
  <a href="https://www.nuget.org/packages/Toamaisutaa.AspNetCore"><img src="https://img.shields.io/nuget/v/Toamaisutaa.AspNetCore?color=0d1117&label=NuGet" alt="NuGet" /></a>
  <a href="https://www.nuget.org/packages/Toamaisutaa.AspNetCore"><img src="https://img.shields.io/nuget/dt/Toamaisutaa.AspNetCore?color=0d1117&label=downloads" alt="downloads" /></a>
  <a href="https://docs.toamaisutaa.pianonic.ch/getting-started"><img src="https://img.shields.io/badge/Getting--Started-Instructions-0d1117.svg" alt="Getting started" /></a>
  <img src="https://img.shields.io/badge/.NET-10-0d1117.svg" alt=".NET 10" />
  <img src="https://img.shields.io/badge/Auth-OIDC-0d1117.svg" alt="OIDC" />
  <img src="https://img.shields.io/badge/License-PolyForm%20Noncommercial-0d1117.svg" alt="PolyForm Noncommercial" />
</p>

---

> **Heads up:** Toamaisutaa is in early development. Expect breaking changes in the public interfaces
> before 1.0, particularly in the store interfaces as two-factor authentication lands.
> **PolyForm Noncommercial 1.0.0** - free for noncommercial use; commercial use needs a separate
> licence. Not an OSI-approved open-source licence.

## What is Toamaisutaa?

トアマイスター / *Toamaisutaa* / "gate master" - German *Tormeister* run through katakana and back out
again. The name is opaque until someone explains the joke, which is the point.

Toamaisutaa is an authentication package for ASP.NET Core. It validates the tokens your identity
provider issues, maps their claims onto a user you can actually store, and - when you have no
identity provider to lean on - issues tokens of its own from a username and a password.

It exists because the same authentication code kept getting written four times, slightly differently
each time: the same JwtBearer block, the same claims fallback chain, the same runtime configuration
endpoint, the same `ICurrentUser`. Four copies drift. This is the copy that does not.

## Install

```bash
dotnet add package Toamaisutaa.OpenIdConnect
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

## Features

- **Any OIDC provider** - every endpoint comes from the issuer's discovery document, so Keycloak,
  Authentik, Pocket ID, Okta and Entra are a configuration change rather than a code change.
- **Claims that survive contact with reality** - a configurable role claim, because issuers disagree
  about whether membership lives in `roles` or `groups`, and userinfo enrichment for the ones that
  keep groups out of the access token entirely.
- **403s that explain themselves** - every refusal logs which claim was read, what the token actually
  carried there, and every claim type present. An empty 403 with a valid token is a miserable
  afternoon; this is the fix.
- **Optional local user** - provisioning is opt-in, written only when a claim actually changed, and
  safe when two first requests race. The package works fine storing nothing at all.
- **Local password login** - for deployments that cannot run an identity provider: PBKDF2 hashing
  with an optional pepper, rotating refresh tokens with reuse detection, lockout, and reset tokens.
  Off unless you ask for it.
- **Its own migrations** - Postgres, SQLite, SQL Server and MySQL, shipped, or apply the entity
  configurations to a `DbContext` you already have.
- **No ASP.NET where it does not belong** - `Abstractions` and `Core` carry no web stack, so a domain
  project can depend on `ICurrentUser` without one.

## Packages

| Package | Contains |
|---|---|
| [`Toamaisutaa.Abstractions`](https://www.nuget.org/packages/Toamaisutaa.Abstractions) | Interfaces, options, DTOs. No dependencies at all |
| [`Toamaisutaa.Core`](https://www.nuget.org/packages/Toamaisutaa.Core) | Claims mapping, provisioning, hashing, lockout. No ASP.NET, no EF |
| [`Toamaisutaa.OpenIdConnect`](https://www.nuget.org/packages/Toamaisutaa.OpenIdConnect) | `AddToamaisutaaBearer`, JWT validation, userinfo enrichment |
| [`Toamaisutaa.AspNetCore`](https://www.nuget.org/packages/Toamaisutaa.AspNetCore) | Authorization, `ICurrentUser`, endpoints |
| [`Toamaisutaa.EntityFrameworkCore`](https://www.nuget.org/packages/Toamaisutaa.EntityFrameworkCore) | Entities, configurations, stores, `ToamaisutaaDbContext` |
| [`Toamaisutaa.EntityFrameworkCore.Migrations.Postgres`](https://www.nuget.org/packages/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres) | The Postgres migration set |
| [`Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite`](https://www.nuget.org/packages/Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite) | The SQLite migration set |
| [`Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer`](https://www.nuget.org/packages/Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer) | The SQL Server migration set |
| [`Toamaisutaa.EntityFrameworkCore.Migrations.MySql`](https://www.nuget.org/packages/Toamaisutaa.EntityFrameworkCore.Migrations.MySql) | The MySQL migration set |

## Documentation

**[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)**

- [What is Toamaisutaa?](https://docs.toamaisutaa.pianonic.ch/intro)
- [Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)
- [OIDC bearer validation](https://docs.toamaisutaa.pianonic.ch/oidc)
- [Local password login](https://docs.toamaisutaa.pianonic.ch/password-login)
- [Storage and migrations](https://docs.toamaisutaa.pianonic.ch/storage)
- [Developer setup](https://docs.toamaisutaa.pianonic.ch/dev-setup)

## Get started (development)

Prerequisites: **.NET 10 SDK**, **Docker** for the sample's identity provider.

```bash
dotnet build Toamaisutaa.slnx
dotnet run --project src/Toamaisutaa.Core.Tests/Toamaisutaa.Core.Tests.csproj   # TUnit, runs itself
cd samples/MinimalApiSample && dotnet run                                        # -> http://localhost:5203
```

## Licence

[PolyForm Noncommercial 1.0.0](LICENSE.md).
