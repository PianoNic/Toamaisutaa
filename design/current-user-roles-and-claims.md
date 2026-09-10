# Roles and claims on `ICurrentUser` (issue #64)

Two decisions in this change are not obvious from the diff.

## The new members are defaulted, not abstract

`Roles`, `IsInRole` and `FindClaim` carry a default implementation on the interface: an empty list,
a false, a null.

`ICurrentUser` is public and is the one interface in this package an application is actually likely
to implement itself - a test double, a worker that runs the same domain services outside a request,
an application that authenticates in some way this package knows nothing about. Adding three
abstract members breaks every one of those at compile time, in a package whose whole pitch is that
a domain project can depend on this interface.

The default is also the right answer rather than a placeholder: an implementation with no claims to
read genuinely carries no roles, and the issue asks for exactly that ("non-HTTP implementations
return empty"). `IsInRole` defaults to a lookup in `Roles`, so an implementation that can answer for
roles overrides one member and gets the check for free.

## `Roles` reads two claim types, not one

The issue says "read from the configured `RoleClaim`". The implementation reads that first and then
falls back to `ClaimTypes.Role`, deduplicating.

`Subject` and `Name` already make the same fallback for the same reason. `AddToamaisutaaCurrentUser`
is registered independently of `AddToamaisutaaBearer`, so the principal on the request did not
necessarily come from this package's bearer pipeline - cookies, a scheme of the application's own, a
principal enriched from a table after authentication. Roles land under the .NET claim type in all of
those, and that is also the type `RequireRole` would read there, so reading only the configured JWT
claim would report an empty list for a caller the authorization layer considers an admin. Reporting
less than `[Authorize]` sees is the failure worth avoiding here.

Both claim types are covered by a test, the second by an endpoint that replaces `HttpContext.User`
with a principal from a scheme the package did not issue.

## What was left alone

`IsInRole` compares ordinally, which is what `ClaimsIdentity` and therefore `RequireRole` do. Case
insensitivity would grant on a value the authorization layer refuses, which is worse than being
strict in both places.
