# Passkeys: where the pieces had to live, and what moved to let them

Issue #73. The brief said "separate package `Toamaisutaa.Passkeys` so nothing lands in `Core`",
which settles the WebAuthn dependency and settles nothing else. Three things did not fall out of it.

## 1. The entity is in `Abstractions`, not in the passkey package

`ToamaisutaaPasskeyCredential` and `ToamaisutaaPasskeyChallenge` sit beside every other entity, and
`Toamaisutaa.EntityFrameworkCore` configures them, holds the store, and ships them in all four
migration sets.

The alternative was keeping them in `Toamaisutaa.Passkeys` and having the storage package pick them
up. That inverts the dependency: `Toamaisutaa.EntityFrameworkCore` would reference an opt-in feature
package, and every consumer who never wanted passkeys would carry FIDO2 through the graph. The other
alternative - a fifth migration assembly owned by the passkey package - means a deployment running
two `__EFMigrationsHistory` sets against one database, and `ToamaisutaaDbContext` is a single context
by design.

So the layering rule that actually applies is the one about `Abstractions` carrying zero package
references. It still does: these are two POCOs and two interfaces. The FIDO2 dependency is in exactly
one project, which is what the brief asked for.

The cost, stated plainly: `ToamaisutaaDbContext` grows two tables that a deployment without the
passkey package never writes to. That is already true of the two-factor and trusted-device tables
under their own opt-in registrations, so it is the shape this repository already lives with.

## 2. `LocalSessionIssuer` came out of `PasswordSignInService`

A passkey assertion ends in the same thing a password sign-in does: an access token, a refresh row
carrying the family, and a `SignInSucceeded`. That code was `PasswordSignInService.IssueAsync`, and
it was private.

Copying it into the passkey package would have produced two answers to "what does a token carry
now?" - which is precisely the question this repository has got wrong three phases running (`amr`,
then `toa_2fa_source`, then `toa_2fa_at`). A fourth answer living in a second file, out of sight of
whoever next adds a claim, is the same bug with better camouflage.

So it moved to `Toamaisutaa.Core/LocalSessionIssuer.cs`, `internal`, with
`InternalsVisibleTo("Toamaisutaa.Passkeys")` alongside the entries `AspNetCore`, `OpenIdConnect` and
the Argon2 package already have. `PasswordSignInService.IssueAsync` still exists and still owns what
only a password sign-in has - the recovery-code warning and the device token - and delegates the rest.

It has its own tests now (`LocalSessionIssuerTests`), which is a small gain on top: what the refresh
row keeps was previously only ever asserted through a password sign-in.

## 3. `TwoFactorEnrolmentRequired` had to learn about the sign-in it is on

`TwoFactorGate.MustEnrolAsync` answers "is this user unenrolled while `RequiredForAll` demands it".
For a password or device sign-in that is the whole question, because an enrolled user answers no
either way. For a passkey it is the wrong question: the user may have no TOTP enrolment at all and
still have just proved two factors.

The issuer now asks it only when the sign-in presented no second factor:

```csharp
TwoFactorEnrolmentRequired = request.TwoFactorSource is null
    && await twoFactor.MustEnrolAsync(user.Id, cancellationToken),
```

Behaviour-preserving for every existing path - the gate already answered no wherever
`TwoFactorSource` is set - and it is what makes the issue's acceptance line true. Both halves are
tested, because the short circuit taken too far would switch enforcement off for everybody.

## Deliberate narrowings

**No identifier at sign-in.** `/assertion/begin` takes no user name and returns an empty
`allowCredentials`. Accepting one would mean a per-user credential list on an anonymous endpoint,
whose length answers "does this account exist" whatever the body says. Discoverable credentials
remove the need for it, so the endpoint has nothing to leak. The follow-on is that
`residentKey: required` is not configurable: a non-discoverable credential would register happily and
then never appear at a sign-in prompt, which is a worse failure than refusing it up front.

**No passkey as a second factor after a password.** The issue's framing mentions "a second factor
beside TOTP", but its acceptance line describes the passkey sign-in itself satisfying
`RequiredForLocalLogin` and `RequiredForAll` - which is what is built. Redeeming a passkey against a
`TwoFactorChallengePurpose.SignIn` challenge is a second ceremony with its own store interactions and
its own way to go wrong, and nothing in the issue needs it. It is additive later.

**The challenge is spent before the assertion is verified**, which is the opposite of the two-factor
challenge next door. A mistyped six-digit code is a routine human error and deserves a second try; an
authenticator response is produced by software in one shot, so a failed one is not a typo - and
leaving the challenge live would hand an attacker unlimited attempts against a single one. The test
that covers this had to be rewritten once: replaying the identical bytes passes with the consumed
check deleted, because by then the signature counter refuses it. Two assertions over one challenge,
the second with a higher counter, is the version that actually tests the rule.

## Fido2 4.0.1

`Fido2` (fido2-net-lib), pinned at 4.0.1 - the current stable line; 5.0.0 is in preview. The .NET 10
passkey support is inside ASP.NET Core Identity, bound to that library's user manager and stores, so
a package that is not Identity cannot reuse it.

It brings `NSec.Cryptography`, which carries native libsodium assets - the first native dependency
anywhere in this repository. It is only reached for Ed25519 keys, which no mainstream authenticator
produces, but it is in the package graph regardless and is worth knowing about before someone
publishes to a platform with no matching RID.

## What was not verified

The four migrations scaffold and the SQLite one is exercised by the whole HTTP suite. The other three
have not been applied to a real server. The one to watch is MySQL: `CredentialId` is
`varbinary(256)` with a unique index, which is well inside InnoDB's 3072-byte key limit, but that is
an argument rather than a green run.
