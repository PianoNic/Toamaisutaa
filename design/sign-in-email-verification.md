# Requiring a verified address to sign in

`LocalLogin:RequireVerifiedEmailForSignIn`, off by default. A self-registered account could sign in
on an address nobody had proven; with this on, registration and a right password answer an
`email_verification_required` challenge instead of tokens, and a mailed six-digit code finishes it.

## Decisions

- **The proof is an abstraction.** `IEmailVerificationMethod` owns issuing and checking; the default
  is the code. The library keeps the challenge, lockout, the writes a proven address makes, and how
  the sign-in finishes, so a replacement cannot get those wrong.
- **The challenge has the two-factor challenge's shape.** A branch flag (`email_verification_required`)
  and a flat body, rather than a nested `challenge` object, because `/auth/login` already answers a
  string `challenge` and one field changing type between shapes is worse for a typed client.
- **The code is keyed to the signing key, not to the challenge.** Keying it to the challenge secret
  needs no key at all, but then a sign-in inside the cooldown, which mails nothing, would hand back a
  challenge the code in the mailbox cannot answer. HKDF over `LocalLogin:SigningKey`, or the active
  asymmetric key's private half, with its own label, the way recovery codes derive from the TOTP key.
  Rotating the signing key retires the codes in flight, which last fifteen minutes.
- **Cooldown is read from the code table**, not `MailRequestCooldown`'s in-memory gate, so every
  instance agrees.
- **Wrong codes reserve against the credential's lockout** before they are compared, like a wrong
  second-factor code. A code that was not outstanding is refunded: nothing was guessed.
- **Refresh is refused** for a password-started family of an unverified credential, with the family
  revoked as `email-not-verified`. Otherwise turning the option on leaves every unverified account its
  sessions for ninety days. Passkey, provider and magic-link families are left alone.
- **Magic links need no decision**: one is only ever sent to a verified address.
- **A credential with no address cannot sign in by password** with the option on. Otherwise an account
  whose unproven address was released to the account that proved it would be left with no address
  and no check. Registration and admin creation therefore require one.
- **No `rememberDevice` on verify-code**: a trusted device stands in for a second factor, and none has
  been presented. A second-factor account goes on to `/auth/2fa/verify`, which takes it.
