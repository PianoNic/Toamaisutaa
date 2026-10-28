# A passkey as a second factor (#393)

Only a confirmed TOTP enrolment triggered the second-factor challenge, so an account whose only
second factor was a passkey was still signed in by a password alone, or a magic link alone.

## What changed

- `TwoFactorGate.RequiresChallengeAsync` is true for a confirmed TOTP enrolment **or** a registered
  passkey (when the challenge store exists, so there is a second step to send the user to).
- `HasTotpAsync` for the two places only a code can answer: step-up, which has no passkey ceremony,
  and a passkey assertion without user verification, where a passkey answer would be possession
  twice.
- `POST /auth/passkeys/second-factor/begin` and `/complete`. Begin peeks the sign-in challenge and
  stores a `SecondFactor` passkey challenge bound to its user, with `allowCredentials` naming that
  user's passkeys (no enumeration concern: the caller already proved the first factor). Complete
  verifies the assertion through the same `VerifyAssertionAsync` as passkey sign-in, then spends the
  sign-in challenge with `RedeemWithPasskeyAsync`, and issues `amr` = first factor + `hwk` + `mfa`,
  `toa_2fa_source` = `passkey`.
- `second_factors` on the challenge response (`otp`, `passkey`), defaulting to `otp`.

Breaking: an account with a passkey and a password now gets a challenge on password sign-in, so a
client has to offer the passkey step.

## A bug it found

The tampered-signature test for the new endpoint used 70 zero bytes, which is not DER. Fido2 throws
`ArgumentOutOfRangeException` for that rather than a verification failure, and it escaped as a 500 -
on `/assertion/complete` too, where it had always been. The existing test used a well-formed
signature from the wrong key. `ArgumentException` is now caught with the other malformed-field
exceptions, and `/assertion/complete` has its own test.

## Guards that back each other up

- A passkey of another account is refused by Fido2's `allowCredentials` check and by the explicit
  owner check. Either alone is enough; removing both reddens the test.
- A ceremony begun with one sign-in challenge and finished with another's is refused by the user-id
  check and by the challenge's security stamp, which never matches another account's.

## Verification

Ten mutations; each guard either reddens its own test or, as above, only does so together with the
guard backing it up.
