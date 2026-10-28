# Email flows, audit events and external login (#400)

Six items, re-verified first; all held. Four are code, two are documentation, for the reasons below.

## External login (the serious one)

`UserInfoClaimsEnricher` merged every claim userinfo returned, and `RequireFreshSecondFactor` read
`toa_2fa_at` from whatever issued the token. A provider whose profile attributes users can edit
would let one put `toa_2fa_at` (or `amr`) there and pass a freshness policy, or the package's own
`Toamaisutaa.TwoFactor` policy, without a second factor anyone checked.

- Userinfo now contributes the role claim only, which is what it is fetched for.
- `RequireFreshSecondFactor` reads `toa_2fa_at` only from a claim whose issuer is `LocalLogin:Issuer`,
  and its clock is the registered `TimeProvider`, the one that stamps the claim. There was no HTTP
  test of this policy before; writing one showed it compared against the real clock, so a token from a
  moved test clock read as from the future. The docs' hand-written version of the check had the same
  issuer hole and now checks it.
- `ExternalUserProfile.EmailVerified` carries `email_verified`, for a custom policy that links by email.

The two guards back each other up for a userinfo `toa_2fa_at`: a merged claim carries the local
authority as its issuer, so the freshness check refuses it either way. What only the role-only merge
stops is userinfo's `amr` satisfying `Toamaisutaa.TwoFactor`, and the test pins that.

## `/auth/email` no longer tells a signed-in caller which addresses have accounts

A proven address held by another account now answers 204, exactly as a sent link does, keeps the
cooldown, issues no link, and calls `IEmailVerificationNotifier.SendAddressInUseAsync`, which tells the
address's owner. Its default sends nothing. Not the verification overload with an empty token: a
notifier implementing only the old method would have mailed a broken link.

## Link templates must be https

`LinkTemplates.Problem`, which every SMTP startup check uses, refuses anything but an absolute
`https://` link, with plain `http://` allowed on loopback. The docs recommend the token in the fragment.

## Audit events

`ActorSubject` on every event, filled in by the publisher from an `IAuthenticationActor` the ASP.NET
layer implements from the request's `sub` - so an administrator's action names the administrator
without every service method growing an actor parameter. New events: `account-created` (with its
source), `invitation-sent`, `password-reset-requested`, `magic-link-requested`,
`email-change-requested`. External-login creation publishes when a publisher is registered.

## Documented instead of built

- **A notice to the old address** on an address or password change: every change already publishes an
  event, `EmailChanged.PreviousEmail` included, and a sink is how this package tells anyone anything.
  The docs show the sink.
- **The mail queue can be filled.** A per-domain cap is beaten by using many domains, and the real loss
  is a full or restarted in-memory queue. The docs point at a durable outbox notifier.

## Verification

Twenty mutations across AspNetCore, Core and SMTP tests, each reddening its own test once the tests were
right. Two first-round survivors were the tests' fault, not the code's: claims stamped with the real
clock read as from the future against the app's clock and were refused whatever their issuer, so the
tests now backdate them into the window.

One full-suite run hit a timing flake in the discovery health check's probe test, which passes alone
here and on main.
