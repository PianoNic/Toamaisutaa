# Per-source lockout (#390)

Wrong passwords at sign-in were counted against the account alone, and a locked account refused the
right password before checking it. Anyone who knew a user name could keep its owner locked out from
anywhere, five guesses every fifteen minutes.

## The choice

Three options were weighed: count per (account, source) with an account-wide ceiling; keep the
account lock but let a trusted device past it; or replace the lock with progressive delays. The
owner chose the first, with two requirements from Schuly's deployment added: both thresholds
configurable, and a trusted device let past the per-source lock, because a school sends every pupil
and teacher out through one public address and per-source counting alone does nothing there.

## What counts where

| Failure | Counted on | Why |
|---|---|---|
| Wrong password at sign-in | `ToamaisutaaSignInThrottles`, per source and on the `*` ceiling row | Anonymous: anyone can make one |
| Wrong second-factor code, wrong current password | The credential, as before | Needs the password or a session already |

They used to share the credential's count. Raising the threshold for sign-in alone would not have
worked: anonymous wrong passwords would still have filled the count that the owner's own wrong codes
lock on, so a stranger could push the owner one typo from a lock. Splitting the counters is what makes
the anonymous path unable to touch the owner.

A lock on the credential still refuses sign-in. Only someone holding the password or a session can
set it now (#392 is about making that escalate).

## Sources

- IPv4 by address, IPv6 by /64. A subscriber is handed a /64, so counting single v6 addresses would
  give each one a fresh budget.
- A caller presenting a valid trusted-device token is counted on that device's family instead of
  its address, and is not held to the ceiling. The device token is peeked, not redeemed: redeeming
  rotates it, and only a right password may do that.
- The table stores a SHA-256 of the source, never an address.

A stolen device token is therefore worth five guesses per window, the same as one address, not an
unlimited way past the ceiling.

## Right passwords

- The source's own count is cleared, so typos before a right password are forgiven.
- The ceiling gives back only this attempt. Clearing it would let guesses spread across addresses be
  wiped out by the owner signing in between them.
- Either is refused, clearing nothing, when other attempts locked it while this password was being
  hashed. That keeps the earlier rule that one right guess in a parallel wave does not unlock what
  the wave just locked (`SignInLockoutRaceHttpTests`, which caught a first version that did).
- An attempt refused by the ceiling gives its source reservation back: the owner retrying from a
  clean address did not guess, and should not find that address locked once the ceiling lifts.

Setting a new password (reset, change, administrator) deletes every throttle row for the account. A
Core test caught this: a reset used to clear the lock because the lock lived on the credential.

## Tests that changed meaning

- `A_right_second_factor_does_not_clear_wrong_passwords` used a wrong front-door password as its fifth
  failure. That no longer reaches the credential, so the fifth failure is now a wrong code at sign-in,
  which does, and the assertion is unchanged.
- `A_window_restart_from_a_stale_read_conflicts_with_one_that_landed` seeded the credential's count
  with a wrong front-door password; it now uses a wrong current password.

## Verification

Thirteen mutations, each reddening the test named for it, including the EF store's conditional write
made unconditional (caught by twelve parallel guesses) and the reset no longer clearing the rows
(caught by the existing Core test). One survived the first round, a right password refunding itself
rather than clearing its source, and a test was added for it.

Migrations applied from empty on SQLite and in a throwaway Postgres 18 container. SQL Server and
MySQL scripted only; the MySQL primary key is about 400 bytes under utf8mb4, inside the limit.
