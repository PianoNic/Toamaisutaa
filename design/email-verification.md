# Email verification: the four decisions issue #70 did not settle

Issue #70 named `EmailConfirmedAt`, a token store shaped like the reset one, `POST /auth/email/verify`
to redeem, `POST /auth/email` to request a change, a notifier with an SMTP implementation, and an
option to require a verified address before a password reset. Four things it did not say, and what
was done instead.

## There is no resend endpoint

The issue names two routes, and the flow they describe issues a token only when somebody asks to
change their address. A freshly registered account would then have no way to verify the address it
already has, which is exactly the account the reset option locks out.

The answer is that `POST /auth/email` accepts the address the credential already holds, and that is
the resend: same body, same password, same link, and redeeming it stamps the address confirmed
without moving anything. A third route would have been the obvious alternative, and it was not
added, because "change my address to the one I have" is not a special case of anything - it is the
same operation with the same proof.

## The current password is required even for that

Requiring a password to be handed a link to the mailbox already on file protects nothing: the mail
goes where the account's mail already goes. Making the requirement conditional on whether the
address is changing was the alternative, and it was rejected for being a rule with a branch in it -
the kind that gets remembered as "no password needed for /auth/email" by whoever reads it quickly.

One rule: `/auth/email` always needs the current password.

## `IUserStore` gained `SetEmailAsync`, which is source-breaking

The credential holds the login identifier; `ToamaisutaaUser.Email` is the profile field OIDC
provisioning rewrites. Verification writes the credential, and that is the whole point of the
separation.

But `IPasswordResetNotifier` and `IInvitationNotifier` are handed a `ToamaisutaaUser` and address
their mail to `user.Email`. Leaving the profile field behind would mean a verified change of address
followed by a reset link mailed to the address the person just left - a working delivery to a mailbox
they may no longer control. So redemption writes both, and `IUserStore` needed a member that could.

Same shape as `SetUserNameAsync`, added for invitations in the phase before this one, and documented
the same way in `docs/storage.md`.

## The reset option is a lockout waiting to happen, and startup only catches half of it

`RequireVerifiedEmailForPasswordReset` closes a real hole - an unverified address may be a typo, or
may belong to somebody else - and opens another: every credential already in the database has
`EmailConfirmedAt` null, so switching it on takes password reset away from all of them at once, and
the way back is `/auth/email`, which needs the password they came here without.

Startup refuses the one case that has no way out at all: the option on with no
`IEmailVerificationNotifier` registered, where nothing can ever verify anything. The other case - the
option on over an existing database - cannot be told apart from a fresh deployment by a startup
check, so it is a `::: danger` block in `docs/email-verification.md` and the default is off.

The log line is the rest of the mitigation. `PasswordResetRequestOutcome.EmailNotVerified` names the
user id and the option, because from outside this is indistinguishable from every other reason
`/auth/password/forgot` answers 204 and no mail arrives.
