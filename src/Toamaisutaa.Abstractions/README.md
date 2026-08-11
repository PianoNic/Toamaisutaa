# Toamaisutaa.Abstractions

The contracts for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa), an authentication package
for ASP.NET Core. Interfaces, options, DTOs and entities - **no implementation and no dependencies of
any kind**, not even `Microsoft.Extensions.*`.

That is the whole point of it. Two kinds of project should install this one directly:

- **A domain or application layer** that wants to know who the caller is. Depend on `ICurrentUser`
  here and you get the subject and the display name without ASP.NET Core, Entity Framework, or a JWT
  library arriving in your domain project.
- **Anything replacing a piece of Toamaisutaa.** Every seam in the package is an interface declared
  here, so a custom store, hasher or claims mapper compiles against this alone.

Everyone else gets it transitively and never has to think about it.

## What is in it

**Where the caller comes from**

| Type | Is |
|---|---|
| `ICurrentUser` | The subject and name from the token, and the local user row if you provision one |
| `IUserStore`, `IExternalLoginStore` | Reading and writing users and their identity-provider links |
| `IClaimsProfileMapper` | Turning a `ClaimsPrincipal` into a profile, for issuers that name things unusually |
| `IProvisioningPolicy` | Whether a first sign-in creates a user, links to an existing one, or is refused |

**Local password login**

| Type | Is |
|---|---|
| `IPasswordSignInService` | Sign in, refresh, sign out, and finish a two-factor challenge |
| `IPasswordAccountService` | Register, set or change a password, request and complete a reset |
| `IPasswordHasher` | Hashing and verification. Replace it to use Argon2 or anything else |
| `IPasswordValidator` | What counts as an acceptable password |
| `IPasswordResetNotifier` | **You must implement this.** The package deliberately ships no way to send mail |
| `IAccessTokenIssuer` | Minting the access token a local sign-in returns |
| `IUserRoleProvider` | Where roles come from for a locally issued token |

**Two-factor authentication**

| Type | Is |
|---|---|
| `ITwoFactorService` | Enrolment, confirmation, disabling, recovery codes |
| `ITotpProvider`, `IRecoveryCodeProvider` | Code generation and verification |
| `ISecretProtector` | Encrypting the TOTP secret at rest. Replace it to keep the key in a vault or an HSM |

**Entities**, as plain classes with no attributes and no navigation properties, so the storage layer
is free to map them however a given database needs: `ToamaisutaaUser`, `ToamaisutaaExternalLogin`,
`ToamaisutaaPasswordCredential`, `ToamaisutaaRefreshToken`, `ToamaisutaaPasswordResetToken`,
`ToamaisutaaUserTwoFactor`, `ToamaisutaaRecoveryCode`, `ToamaisutaaTwoFactorChallenge`.

**Options**, one class per configuration section: `ToamaisutaaOidcOptions` (`Oidc`),
`ToamaisutaaLocalLoginOptions` (`LocalLogin`), `ToamaisutaaTwoFactorOptions` (`TwoFactor`),
`ToamaisutaaProvisioningOptions` and `ToamaisutaaAuthorizationOptions`.

## Stability

Pre-1.0, so these interfaces still move - the store interfaces most of all. Breaking changes are
listed in the release notes and the PR is labelled, but if you implement one of these yourself,
pin the version and read the notes before upgrading.

## Documentation

**[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)**

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
