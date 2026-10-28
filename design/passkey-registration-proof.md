# Proof for registering a passkey (#394)

A `toa_2fa_at` inside `RegistrationProofWindow` (five minutes) was enough to register a passkey, so
a token captured by a phishing proxy or an XSS right after a second-factor sign-in could add the
attacker's own passkey. That passkey survives sign-out, revoking every session, turning 2FA off and on,
and new recovery codes; only a password change removes it.

## The rule now

| Account | Must send |
|---|---|
| TOTP enrolled | `code` (TOTP or recovery), counted against lockout |
| Password, no TOTP | `currentPassword`, counted as before |
| Neither | nothing more: a second factor within the window is all such an account has |

The proof is in the request, so a stolen token alone no longer registers anything wherever the
account has something to prove. The third row is unchanged and unavoidable: an account whose only
credential is a passkey (or an identity provider) has nothing else to ask for.

Removal keeps its rule; #399 tightens it.

The code is checked by `TwoFactorService.ProveAsync`, the same counted path `/auth/2fa/disable` uses,
rather than a second copy in the passkey package. A missing code is refused without being counted,
so a client that forgot the field does not lock the account; a test pins that, because the first
round of mutations showed nothing else did.

## Notifying the owner

The issue asked for a mail whenever a passkey is added. `passkey-registered` was already published;
the docs show a sink that mails it. A dedicated notifier interface would duplicate the audit sink,
which is where this package already sends consumers for "tell somebody when X happened".
