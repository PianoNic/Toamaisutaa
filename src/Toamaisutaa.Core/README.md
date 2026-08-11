# Toamaisutaa.Core

The logic behind [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa), with **no ASP.NET Core and
no Entity Framework**. It depends on `Toamaisutaa.Abstractions` and `Microsoft.Extensions.*` and
nothing else, so it runs in a worker service, a console app or a test without a host.

Most applications do not install this directly - `Toamaisutaa.AspNetCore` brings it. Install it on
its own when something outside a web request needs to hash a password, verify a TOTP code, or
provision a user from a `ClaimsPrincipal`.

## What is in it

- **Password hashing** - PBKDF2-HMAC-SHA256 at 600,000 iterations, with an optional pepper and
  versioned rotation. Hashes are PHC strings naming their own algorithm and parameters, so changing
  either is a rehash on next sign-in rather than a schema change.
- **Sign-in and account flows** - lockout, rotating refresh tokens with reuse detection and family
  revocation, password reset, and the security stamp that ends outstanding sessions.
- **TOTP** - RFC 6238 with replay protection, recovery codes, and AES-256-GCM encryption of the
  secret at rest. Composed from base class library primitives; there is no TOTP dependency.
- **Provisioning** - turning an identity provider's claims into a local user, deciding whether a
  first sign-in creates or links, and writing only when something actually changed.

Every one of these is registered behind an interface from `Toamaisutaa.Abstractions` with
`TryAdd`, so registering your own first replaces the default.

## Registration

```csharp
services.AddToamaisutaaProvisioning();   // claims mapping, provisioning, account linking
services.AddToamaisutaaTokenCleanup();   // periodic sweep of expired tokens and challenges
```

The password and two-factor services are registered by `AddToamaisutaaPasswordLogin` and
`AddToamaisutaaTwoFactor` in `Toamaisutaa.AspNetCore`, because both need an access token issuer and
endpoints to be useful.

## Documentation

**[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)**

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
