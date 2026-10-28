# Password reset needs a verified address by default (#396)

`RequireVerifiedEmailForPasswordReset` was off, and registration and `/auth/users` store an address
unverified with nothing verifying it on its own. A reset link, or a generated admin password, went to
whatever was typed: `anna@gmial.com` belongs to whoever owns the typo, and that is the account.

## What changed

- The option defaults to `true`.
- The startup check that already refused "option on, no `IEmailVerificationNotifier`" now says the
  option is on by default and names the setting that turns it off. So a deployment with no way to
  verify an address fails at startup rather than silently losing every reset. Breaking, deliberately.
- The provisioning docs steer administrators to invitations, which prove the mailbox.

## Tests

37 existing tests reset addresses they never verified, because that is not what they test. Both
harnesses set the option off with a comment saying so, and four tests run against the shipped value:
nothing is mailed for an unverified reset, nothing for an unverified admin password, startup refuses
without a verification notifier, and the default itself. Putting the default back to `false` reddens
all four.
