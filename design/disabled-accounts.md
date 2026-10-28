# Disabled accounts (#388)

There was no way to remove someone without deleting their account. The admin password reset mailed
the new password to the departing user's own address, and a working mailbox kept magic links and
resets open to them.

## What was added

- `ToamaisutaaUser.DisabledAt`, stored as Unix milliseconds through `InstantConverters` like every
  other instant. Migrations for all four providers.
- `IUserStore.SetDisabledAtAsync`, with a default implementation that throws, so a store written
  before this keeps compiling and fails only at the moment an account is disabled.
- `AdminDisableAccountAsync`, `AdminEnableAccountAsync`, `AdminRevokeSessionsAsync` on
  `IPasswordAccountService`, and `POST /auth/users/{id}/disable`, `/enable` and `/sessions/revoke`.
  They need the admin policy and no notifier, because they send nothing.
- `SignInOutcome.AccountDisabled`, and `AccountDisabled` on both mail-request outcome enums.
- `AccountDisabledException`, answered 403 `account_disabled` by the package's endpoint filter.
- `account-disabled` and `account-enabled` audit events.

## Where it is checked

Password sign-in, two-factor verification, magic-link verification and request, password reset
request and redemption, passkey sign-in, refresh, invitation completion, and
`ICurrentUser.GetOrProvisionAsync`.

**Password sign-in checks before the attempt is reserved**, so a disabled account collects no
failures, and runs the dummy hash so timing matches. Over the wire it is the same 401 as a wrong
password. Telling a caller "disabled" would confirm the account exists to someone without the
password.

**`GetOrProvisionAsync` checks before the stamp.** Disabling moves the stamp too, so a local token
would otherwise get the stale-stamp 401, and a client would refresh and be refused again. A token
from an identity provider carries no stamp at all, so this check is the only thing that refuses it.

**403, not 401.** The token is valid; the account is not.

**Step-up has no check of its own.** Both step-up endpoints resolve the current user first, which
already refuses, and disabling revokes the session step-up requires. A check in the guard could not
be reached over HTTP, so no test could watch it fail, and it was taken out.

## Ordering in `AdminDisableAccountAsync`

The flag is set first, then the stamp moves, then sessions, devices and links go. A sign-in that
reads the user after the flag refuses. One that read it before carries the old stamp, so its refresh
family is refused at the next refresh by both the stamp and the flag.

Passkeys, the password and the second factor are kept, so enabling restores the account exactly.
That is the difference from the password-reset path, which deletes passkeys because a reset means
the credentials may be compromised. Disabling says nothing about the credentials.

A repeated disable keeps the original `DisabledAt`, so the row still says when access was first cut,
and revokes again.

## Verification

Every check was removed in turn and its test watched fail (15 mutations, each reddening the test
named for it). The per-gate tests set the flag directly through `IUserStore` without revoking
anything or moving the stamp; otherwise the revocation would keep them green with the gate deleted.

One mutation survived the first round: removing the row revocation from `AdminRevokeSessionsAsync`
left the test green, because the moved stamp alone refuses the old refresh token. What only the
rows decide is the session list, so the test now asserts the old session is gone from it.

Migrations: SQLite applied from empty to a file, Postgres applied in a throwaway `postgres:18`
container. SQL Server and MySQL were scripted, not applied: each is a single nullable `bigint`
column with no index, so the MySQL key-length limit does not come into it.
