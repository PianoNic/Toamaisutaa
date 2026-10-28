# Escalating lockout (#392)

A lock on the account always lasted `LockoutDuration` and cleared the count, so somebody holding the
password could guess five codes every half hour forever: about 240 a day, enough to find a six-digit
code within a year with good odds.

## What changed

- `LockoutStrikes` on the credential and on the two-factor enrolment: locks set since the last
  completed sign-in. Each lock lasts `LockoutDuration * 2^(strikes - 1)`, capped by
  `LockoutMaxDuration` (one day). After a few rounds that is five guesses a day.
- A completed sign-in and a new password reset it, through the same `RegisterSuccess` that clears
  the count. A right current password does not: it only refunds its own reservation, as before.
- Only the account's own locks escalate (wrong codes, wrong current passwords). The per-source
  sign-in throttle from #390 does not: it can be set by anyone, and escalating it would hand a
  stranger a longer lock on a shared address.
- `AccountLockedOut.Strikes`, so a sink can tell the owner. The issue asked for a notice after N wrong
  codes; the package has no "security notice" notifier, and the audit sink is already where consumers
  mail from, so the docs show that sink rather than a new interface.

## Store contract

`ITwoFactorStore.UpdateFailedAttemptsAsync` gained an overload carrying the strikes. Its default
calls the old one and drops them, so a custom store keeps compiling and keeps every lock at the first
length. Strikes move only together with `LockedOutUntil`, which is already in the condition, so they
need no condition of their own.

`LockoutPolicy.Refund`'s "a lock set by others counting this right attempt" branch now subtracts the
strike that lock added, and derives when that lock was set from the escalated duration rather than
the base one.

## Verification

Seven mutations, each reddening its own test. The enrolment's strikes being dropped is only visible in
Core.Tests, because the endpoints cannot build an account with no password. Migrations applied from
empty on SQLite and Postgres 18.
