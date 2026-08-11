# What is Toamaisutaa?

**トアマイスター** / *Toamaisutaa* / "gate master" - German *Tormeister* run through katakana and back
out again.

Toamaisutaa is an authentication package for ASP.NET Core. It validates the tokens your identity
provider issues, maps their claims onto a user you can actually store, and - when you have no
identity provider to lean on - issues tokens of its own from a username and a password.

It exists because the same authentication code kept getting written four times, slightly differently
each time: the same JwtBearer block, the same claims fallback chain, the same runtime configuration
endpoint, the same `ICurrentUser`. Four copies drift. This is the copy that does not.

## Two ways in

**OIDC bearer validation** is the recommended path. The authorization-code flow with PKCE runs in
your client; Toamaisutaa validates what it sends, enriches the claims when the issuer keeps group
membership out of the access token, and hands you a local user if you want one.

**Local username and password login** is the fallback, for deployments that cannot run an identity
provider. Turning it on means becoming the identity provider, with everything that implies - so it
is off unless you ask for it, and built to be conservative rather than convenient. It can be paired
with [TOTP two-factor authentication](/two-factor), also off by default.

Use OIDC if you can.

## What it is

- **Bearer token validation.** Every endpoint comes from the issuer's discovery document, so swapping
  Keycloak for Entra is configuration rather than code.
- **A bridge from claims to a user row.** Optional, written only when a claim actually changed, and
  safe when two first requests race.
- **A local login, for when you have no provider.** PBKDF2, rotating refresh tokens, lockout, reset
  tokens and TOTP. Off until you ask.
- **Storage on your terms.** Four databases' migrations, your own `DbContext`, or no database at all.
- **Seams, not assumptions.** Hashing, claims mapping, provisioning, roles and secret protection are
  each one interface you can replace.

## What it is not

- **Not an identity provider.** It does not implement the authorization-code flow, a consent screen,
  or client registration. Keycloak and Pocket ID do that well already.
- **Not a roles system.** There is no roles table. Roles come from your identity provider's token, or
  from an `IUserRoleProvider` you supply.
- **Not a user manager.** There is no admin UI, no user list, no invitation flow.

## Why not ASP.NET Core Identity?

Identity is the closest thing in the box, and the overlap is real: local login, two-factor, EF Core
migrations, and `MapIdentityApi` for register, login and refresh endpoints. If that is all you need,
use it. It ships with the framework and it is far better tested than this.

The difference is who owns the users. **Identity assumes it does** - it is a membership system, and
an application pointed entirely at an external provider leaves most of it, user database included,
with nothing to do. **Toamaisutaa assumes the identity provider does**, and starts from a validated
bearer token.

| | ASP.NET Core Identity | Toamaisutaa |
|---|---|---|
| OIDC / external provider | Not built in | The primary path |
| Its endpoints' tokens | Proprietary, [not JWTs](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization) | Standard JWTs, validated by the same pipeline as your provider's |
| Local user table | Required | Optional |
| Roles | Its own tables | From the token, or an interface you supply |
| UI | Scaffoldable Razor pages | None |

The token format is the one that catches people. Microsoft is explicit that the Identity API's
tokens "aren't standard JSON Web Tokens" and that it "isn't intended to be a full-featured identity
service provider or token server". If a gateway or another service downstream needs to read a claim,
that is a problem you inherit.

**Use Identity** for a self-contained application that owns its users. **Use Toamaisutaa** when
something else already does, or will.

If you need to *be* the identity provider, you want neither - look at
[OpenIddict](https://github.com/openiddict/openiddict-core) or
[Duende IdentityServer](https://duendesoftware.com/products/identityserver), and note that Duende
requires a commercial licence above a revenue threshold.

## The packages

| Package | Contains |
|---|---|
| `Toamaisutaa.Abstractions` | Interfaces, options and DTOs. No dependencies at all |
| `Toamaisutaa.Core` | Claims mapping, provisioning decisions, password hashing, lockout, TOTP. No ASP.NET, no EF |
| `Toamaisutaa.OpenIdConnect` | `AddToamaisutaaBearer`, JWT validation, userinfo enrichment, local token issuance |
| `Toamaisutaa.AspNetCore` | Authorization, `ICurrentUser`, the SPA configuration endpoint, the sign-in endpoints |
| `Toamaisutaa.EntityFrameworkCore` | Entities, configurations, stores, `ToamaisutaaDbContext` |
| `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` | The Postgres migration set |
| `Toamaisutaa.EntityFrameworkCore.Migrations.Sqlite` | The SQLite migration set |
| `Toamaisutaa.EntityFrameworkCore.Migrations.SqlServer` | The SQL Server migration set |
| `Toamaisutaa.EntityFrameworkCore.Migrations.MySql` | The MySQL migration set |

`Abstractions` and `Core` carry no ASP.NET and no Entity Framework, so a domain or application
project can depend on `ICurrentUser` without dragging a web stack behind it.

## Status

Pre-1.0. The shape is settled enough to use and not yet settled enough to promise - expect breaking
changes in the public interfaces before 1.0, the store interfaces most of all. Every one is listed
in the release notes.

Licensed under **PolyForm Noncommercial 1.0.0**: free for noncommercial use, and commercial use
needs a separate licence from the author. It is not an OSI-approved open-source licence, so read
`LICENSE.md` before building a business on it.
