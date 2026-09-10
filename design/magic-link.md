# Magic-link sign-in

Issue #71. An emailed single-use token exchanged for a token pair. What follows is the set of
decisions that were not obvious from the issue text, and the arguments behind them.

## The verified-address rule is not an option

The issue says "unverified addresses must not receive one". It was tempting to mirror
`RequireVerifiedEmailForPasswordReset` and make it a setting, for symmetry.

That symmetry is false. A reset link mailed to a wrong address lets whoever reads it *set a
password*, which the account holder discovers the next time they sign in and which leaves a
`PasswordReset` event behind. A magic link mailed to the same address *is the session*, silently,
with nothing else asked for and nothing to notice. The reset option exists because the
alternative - locking every existing unverified account out of reset - is a real cost somebody
might reasonably decline to pay. There is no equivalent cost here: an account that cannot use a
magic link can still use its password.

So `EmailConfirmedAt is null` refuses unconditionally, and `PasswordLoginStartupCheck` refuses the
one configuration where the rule could never be satisfied - an `IMagicLinkNotifier` registered with
no `IEmailVerificationNotifier` beside it. That mirrors the existing check for
`RequireVerifiedEmailForPasswordReset`, which was added for the same failure shape: quietly sending
nothing forever.

## `amr` carries `email`, which RFC 8176 does not define

`ToamaisutaaDefaults` says the `amr` values here are "standard, not invented", and `StepUpMethods`
says this package "does not invent claims values". `email` is a real exception to that, so it is
worth being explicit about why it was still the right call.

The registry has no value for possession of a mailbox. The candidates were:

- **`pwd`.** A lie. Nothing typed a password, and a policy asking for `pwd` would start passing for
  sessions that never proved one.
- **`toa_email`, or a `toa_2fa_source`-style claim of our own.** Consistent with the prefix rule,
  but it puts a value inside a *standard* claim under a private name, which is the one place the
  prefix rule does not help: a gateway reading `amr` would see a value it has never heard of either
  way, and the prefixed spelling additionally disagrees with every identity provider that offers
  emailed sign-in.
- **`email`.** Not registered, but what providers offering this feature already write, so a policy
  written against one of them keeps working here.

The prefix rule is about claim *names* colliding between two issuers writing the same key. A value
inside `amr` has no such problem - the claim is `amr` either way - so the rule that applies is
"agree with what already exists", and that is `email`.

## The first factor is carried on the challenge row

There are now two ways to arrive at a two-factor challenge, and `VerifyTwoFactorAsync` used to
hardcode `["pwd", "otp", "mfa"]` on the way out. Finishing a magic-link challenge would therefore
have minted a token claiming a password was typed.

`ToamaisutaaTwoFactorChallenge.AuthenticationMethods` fixes that: the issuing path writes what it
proved, and the redeeming path adds `otp`/`mfa` to it. Empty reads as `pwd`, which is what every row
written before this column existed actually was, so the migration needs no backfill.

Step-up deliberately leaves the column empty. It takes its methods from the refresh family it is
elevating - `StepUpMethods(live.AuthenticationMethods, ...)` - because the session, not the
challenge, is the thing whose history matters there.

## No trusted device on `/auth/magic-link/verify`

`SignInAsync` lets a device token stand in for a live second factor. `VerifyMagicLinkAsync`
deliberately does not, and `MagicLinkSignInRequest` has no `DeviceToken` at all.

At `/auth/login` the cached factor sits behind a password that was just verified: one live proof,
one cached. Here it would sit behind a mailbox alone - two cached things, and a full session for
somebody who has neither typed anything nor held the authenticator. The narrowing is deliberate and
documented; it can be widened later without breaking anybody, which is not true in the other
direction.

## The link is spent before the challenge is issued

`MarkConsumedAsync` runs before `IssueChallengeAsync`, so a link that reaches a challenge is spent
whether or not the challenge is finished.

The alternative - spend it only on success - is friendlier to somebody who mistypes a code, but it
leaves a working sign-in credential in a mailbox that has demonstrably already been read once, for
the rest of its lifetime. The challenge itself is the thing that survives a mistyped code, and it
already does: `RedeemChallengeAsync` consumes only on success. A person who abandons the challenge
asks for a new link, which is one click.

## Lockout is not consulted, and not cleared

`SignInAsync` refuses a locked-out account before it verifies anything. `VerifyMagicLinkAsync` does
not check lockout at all, and does not reset the counter either.

Lockout exists to make password guessing expensive. A magic-link token is 32 random bytes handed to
one mailbox; there is nothing to guess, so the counter has no bearing on it - and refusing here
would take the obvious way back ("email me a link instead") away from exactly the person who needs
it, which is also why `/auth/password/forgot` works while locked out.

Clearing the counter was considered, since `ResetPasswordAsync` does clear it on the grounds that
"whoever just proved they own the account should not still be locked out". The difference is that a
reset *changes the password*, so the failed attempts are against a credential that no longer exists.
A magic link changes nothing, so the attempts that tripped the lock are still attempts against the
password that is still there. Leaving the lock in place is the conservative reading, and it is
reversible: the account holder can sign in by link and change their password from inside.

## Fifteen minutes

The only lifetime in this package argued *down* rather than up. `PasswordResetTokenLifetime` is an
hour and `EmailVerificationTokenLifetime` is a day, both because nothing bad happens while those
sit unread. Something does happen while this one sits unread: it stays a session. Fifteen minutes is
long enough for delivery plus a person walking back to their desk, short enough that an archived or
forwarded message stops being an account quickly.

The default email template reads the number out of `LocalLogin:MagicLinkTokenLifetime` rather than
carrying its own `Email:Smtp` setting. Two settings that have to agree eventually stop agreeing, and
the one that would be wrong is the one in front of the person waiting for the link.

## Where the two halves live

`RequestMagicLinkAsync` is on `IPasswordAccountService`, beside `RequestPasswordResetAsync`, which it
mirrors line for line - silent outcomes, notifier failure swallowed into an outcome, always 204.

`VerifyMagicLinkAsync` is on `IPasswordSignInService`, because redeeming one is a sign-in: it needs
`IssueAsync`, the two-factor gate, the session metadata and the event publisher, all of which are
private to that service. A third `IMagicLinkService` would have had to duplicate the issuance
machinery or expose it, and neither is worth the tidier name.

## A note for the next person

`amr` was checked against `RefreshAsync` before this was called done, per the standing rule. The
answer is **carried, already**: `ToamaisutaaRefreshToken.AuthenticationMethods` is stored at sign-in
and replayed on rotation, so `email` survives without a new column. That is asserted at both levels -
`ARefreshedMagicLinkSessionStillSaysEmail` and `A_refreshed_magic_link_session_still_says_email` -
and both were watched to fail with the refresh path mutated to recompute `["pwd"]`.
