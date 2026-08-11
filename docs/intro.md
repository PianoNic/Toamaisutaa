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

- **A resource server's token validation.** Every endpoint comes from the issuer's discovery
  document, so swapping Keycloak for Entra is a configuration change, and every 403 says which claim
  it read and what the token actually carried there.
- **A bridge from claims to a user row.** Turns a `ClaimsPrincipal` into a record you own - created
  on first sight of a subject, rewritten only when a claim actually changed, and safe when two first
  requests race.
- **A local identity provider, when you have none to point at.** Password sign-in with PBKDF2,
  rotating refresh tokens with reuse detection, lockout, reset tokens, and TOTP two-factor
  authentication. All of it off until you ask.
- **Storage, on your terms.** Migrations for PostgreSQL, SQLite, SQL Server and MySQL, or the entity
  configurations applied to a `DbContext` you already have. Or no database at all.
- **Seams rather than assumptions.** Hashing, claims mapping, provisioning decisions, role lookup and
  secret protection are each one interface, registered with `TryAdd`, so supplying your own replaces
  the default without forking anything.

## What it is not

- **Not an identity provider.** It does not implement the authorization-code flow, a consent screen,
  or client registration. Keycloak and Pocket ID do that well already.
- **Not a roles system.** There is no roles table. Roles come from your identity provider's token, or
  from an `IUserRoleProvider` you supply.
- **Not a user manager.** There is no admin UI, no user list, no invitation flow.

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
