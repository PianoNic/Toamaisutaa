# `ICurrentUser.Roles` reads the identity's role claim type (issue #92)

This revises the section "`Roles` reads two claim types, not one" in
[current-user-roles-and-claims.md](./current-user-roles-and-claims.md). That record reasoned about
the `ClaimTypes.Role` fallback only in the under-report direction - the failure it set out to avoid
was `Roles` answering empty for a caller `[Authorize]` considers an admin. The union it chose
over-reports in exactly the same way, and over-reporting is the direction that grants.

`RequireRole` reads neither claim type literally. `ClaimsPrincipal.IsInRole` asks each identity for
`HasClaim(identity.RoleClaimType, role)`, and `ConfigureToamaisutaaJwtBearerOptions` sets
`RoleClaimType` to `Oidc:RoleClaim` for every principal this package's bearer pipeline builds. So on
a token from a WS-Federation-typed issuer, a claim typed
`http://schemas.microsoft.com/ws/2008/06/identity/claims/role` was refused by `Toamaisutaa.Admin`
and reported by `ICurrentUser.IsInRole` on the same request. A service written the way
`docs/getting-started.md` shows let the caller through while the route answered 403, and the
permissive one of the two was the one that is not the authorization layer.

The fix reads what `RequireRole` reads: the configured claim, then each identity's own
`RoleClaimType`. For a cookie or foreign principal that is `ClaimTypes.Role`, because
`new ClaimsIdentity(...)` defaults to it - so the fallback the earlier record wanted is still there,
now derived rather than hardcoded. For this pipeline's own principals it is the configured claim,
which closes the over-report.

It also removes a dependency the earlier shape had on configuration binding.
`AddToamaisutaaCurrentUser` registers `ToamaisutaaOidcOptions` unbound on purpose, so an application
that authenticates with a JwtBearer registration of its own and hands this package no
`IConfiguration` had `Roles` reading the default `roles` while its `Oidc:RoleClaim` was read by
nobody. Reading `RoleClaimType` off the identity answers correctly there without a second
`IConfiguration` overload, which is why one was not added.

The rejection of case-insensitive matching in the earlier record stands, and for the reason this
change borrows: matching on something the authorization layer refuses is worse than being strict in
both places.
