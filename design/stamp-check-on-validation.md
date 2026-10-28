# Comparing the stamp on bearer validation (#389)

The stamp was compared only where `ICurrentUser.GetOrProvisionAsync` resolved the user. Endpoints
that relied on `[Authorize]` or a role, the admin endpoints among them, never compared it, so a
token outlived a password reset by up to `AccessTokenLifetime` plus JwtBearer's five-minute leeway.

## What changed

- `OnTokenValidated` compares a local token's `toa_stamp` with `IUserStore.ReadSecurityStampAsync`
  and fails authentication on a mismatch. **Always** on an endpoint carrying the admin policy (and on
  every endpoint when the admin role is required globally), and everywhere with
  `LocalLogin:CheckSecurityStampOnEveryRequest`.
- `Oidc:ClockSkew`, defaulting to 30 seconds.

## Why authentication and not an authorization requirement

A requirement on the admin policy was the obvious place, but a failed requirement is a 403, and
`OnForbidden` explains every 403 as a missing role. At 2am that log line would send somebody to check
the role claim of a token whose only problem is its age. Failing authentication gives a 401 with
`invalid_token`, which is true, and which a client already knows to answer by refreshing; the refresh
is then refused on the stamp too.

The endpoint is known at that point because routing runs before authentication, so the admin check
reads `IAuthorizeData` off the endpoint metadata.

## No cache

The issue suggested a short cache. The read is a primary-key projection, admin endpoints are few, and
the every-request mode is opt-in. A cache would reopen exactly the window this closes, so there is
none.

## What it does not cover

- Removing a role does not move the stamp, because roles come from the consumer's
  `IUserRoleProvider`. The docs say to call `AdminRevokeSessionsAsync` after taking a role away.
- An identity provider's token carries no stamp and is left alone: only the provider can revoke it.
- Signing out one session does not move the stamp, so its access token lives out its lifetime.

## The leeway and the test clock

Thirty seconds broke sixteen HTTP tests. They advance `MutableTimeProvider` past TOTP steps, tokens
are stamped from that clock, and the bearer handler checks `nbf` against the system clock, so tokens
arrived "from the future" by more than the leeway. The harness now sets `Oidc:ClockSkew` to five
minutes with a comment saying why, and the leeway test removes that override so it runs against the
shipped default.

## Verification

Six mutations, each reddening the test named for it: the leeway removed, admin detection disabled,
the opt-in ignored, the comparison always passing, the check applied everywhere, and the event not
calling the check at all.
