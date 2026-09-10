# A passkey is a credential, so it gets a credential's rules

Issue #104. Five review findings on the passkey surface, four of them one shape: the package treated
a passkey as a setting on an account rather than as a way into it. A setting is added with a bearer
token and survives a password reset. A credential is neither.

## Registering asks for proof, and takes two kinds

`/register/begin` refuses a caller who has shown nothing but a bearer token. Two proofs are
accepted, and both already exist in the package:

- `currentPassword`, the way `/auth/email` asks for one;
- a session whose `toa_2fa_at` is inside `Passkeys:RegistrationProofWindow`, which is the claim
  `RequireFreshSecondFactor` reads. A passkey sign-in and a `/auth/2fa/step-up` both set it.

The proof sits on `begin` rather than on `complete`. `complete` redeems a challenge that `begin`
issued against the account, and nothing else can produce one - so a check on `begin` covers both
halves, and it fails before the browser prompt opens rather than after the user has touched their
authenticator.

**Why not require a WebAuthn step-up instead** - an assertion with an existing credential before a
new one is allowed. It is the stronger ceremony, and it is unavailable to the account that most
needs to register: the one with no passkey yet. It would also be a third proof mechanism where the
package already has two that work.

The narrowing this leaves, stated plainly: an account with no local password, whose token was issued
by an identity provider and therefore carries no `toa_2fa_at`, cannot register a passkey without
enrolling a second factor here first. That is a real regression for that account, and the
alternative is an endpoint where any token at all mints a permanent credential.

## Setting a password deletes the passkeys, including the self-service change

`ResetPasswordAsync`, `SetPasswordAsync` and `AdminSetPasswordAsync` already bump the security stamp
and revoke sessions, reset tokens, email-verification tokens and trusted devices. Passkeys join that
list.

The argument against including `SetPasswordAsync` - the routine change, where the caller proved the
current password - is that it costs a re-registration per device for something the account holder
did deliberately. The argument for is that whoever knew the password could register a passkey under
the rule above, so a password change that leaves one standing leaves the thing the change was for.
Trusted devices are already revoked on exactly this reasoning; the difference is only that a passkey
costs one browser prompt to put back.

It is a deletion rather than a disable flag: there is no column for one, and a credential that exists
but cannot be used is a second state for every query on this table to get right.

`IPasskeyCredentialStore.DeleteAllAsync` is the interface change that makes it possible - hence the
`breaking` label. `Core` resolves the store through `IServiceProvider`, the way it resolves the
optional notifiers, so it gains no reference to a package that carries FIDO2.

## An unverified assertion goes through the two-factor gate

`TwoFactorGate.RequiresChallengeAsync` says in its own summary that enrolment alone decides a
challenge, in every enforcement mode. The password and magic-link paths honour that; the assertion
path did not consult the gate at all.

A verified assertion still passes straight through, which is the whole point of issue #73 - one
gesture proved both factors. An assertion with UV clear proved possession alone, so for an account
with a confirmed enrolment it now answers the `two_factor_required` shape `/auth/login` answers with,
carrying `hwk user` as the first factor. The finished token reads `hwk user otp mfa`.

Refusing such an assertion outright was the other option. Challenging is strictly better: the user
holding a PIN-less security key and their authenticator app has both factors and gets in, and a
thief holding the key alone does not.

## Two smaller ones

**The malformed-authenticator-data 500.** `AuthenticatorData.Parse` was being called ahead of
`MakeAssertionAsync` purely to read the UV bit, and it throws `CborContentException` for data whose
extension flag is set with no CBOR behind it - neither of the two exceptions the block caught.
Removing our own parse was not enough: the library parses the same bytes before it validates them
and throws the same exception from inside `MakeAssertionAsync`, which the HTTP test showed. So the
catch is there, and the UV bit is read off the flags byte the specification fixes at offset 32.
`System.Formats.Cbor` needs no package reference - it is in the .NET 10 shared framework.

**The `Location` header on the 201.** It was a relative reference beginning with the user id and
resolved to a path this package does not map. Dropping it beats correcting it: there is no route
that serves one credential (only `DELETE /auth/passkeys/{id}`), so the corrected header would name a
405. Every other 201 in the package sends no Location either.
