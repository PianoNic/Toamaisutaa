# Brokered sign-in through hoster-configured providers (#419)

Requested by the Schuly session: zero, one or several OIDC providers next to local login, configured
by whoever hosts the application, ending in the application's own tokens.

## Where it lives

In `Toamaisutaa.AspNetCore`, not a package of its own. Passkeys got their own package to quarantine
Fido2; this needs nothing beyond what `AspNetCore` already carries through `OpenIdConnect`
(`Microsoft.IdentityModel.Protocols.OpenIdConnect` via JwtBearer), so a separate package would be a
second install step that isolates nothing. `AddToamaisutaaExternalLogin` is opt-in and maps nothing
without providers.

## No cookies

The issue asked for HttpOnly cookies on the web hand-off. The package sets no cookies anywhere: every
sign-in returns JSON and the [SPA page](../docs/spa.md) leaves transport to the application. Adding
cookies for one sign-in path would have been a second token transport with its own CSRF story.
Instead both web and native clients use the same hand-off: the client sends its own PKCE challenge to
`/start`, gets a short single-use code on the return URL, and exchanges it with the verifier. A SPA
can do PKCE as easily as an app, and the exchange answers the exact `/auth/login` shapes, so a client
handles one sign-in contract.

## One row per sign-in

`ToamaisutaaExternalLoginRequests` holds the whole life of one sign-in: state, nonce and our verifier
toward the provider until the callback, then the exchange code hash, the user and the stamp until the
exchange. One `ExpiresAt` serves both phases (it is moved forward at the callback), which keeps the
cleanup query a single range delete. Both phases are spent by conditional writes, so two callbacks or
two exchanges race to one winner.

The upstream verifier is stored in clear. It is worthless without the provider's code, lives ten
minutes, and the token endpoint needs it back verbatim; hashing it is not possible.

## Exchange spends before it compares

A wrong verifier spends the code. Otherwise a code read off a redirect is an oracle with as many
guesses as the rate limiter allows. The verifier is 256 bits, so this is belt and braces, but it
costs a legitimate client nothing: it never sends a wrong one.

## What the provider says is not taken at its word

- `amr` from the provider is ignored; the session gets `fed` only. The CLAUDE.md question for a new
  method: **carried** - it goes through `LocalSessionIssuer` onto the refresh row like every other
  method, and the 2FA challenge carries it into `/2fa/verify`. A test refreshes and checks it.
- No new claim was added. The provider key was considered for the access token and left off: it would
  have to be carried on the refresh row for nothing any policy reads. The audit event carries it.
- The profile is written on creation only. Syncing on every sign-in would let a provider rename, and
  re-address, a local account that merely linked it.

## Address matching

Refused by default with `account_exists`, which does reveal to someone holding a provider identity
that the address has an account here. The alternatives were worse: creating a second account with the
same address leaves two accounts one inbox, and silently linking is the takeover. Since providers are
chosen by the hoster, the addresses they assert are generally verified ones, which is the same
population that could ask for a password reset to that address anyway.

`LinkByVerifiedEmail` is per provider because the trustworthiness of `email_verified` is.

## Linking proof

The same ladder passkey registration uses: a code where TOTP is enrolled, else the password where
there is one, else a fresh sign-in. "Fresh" for a federated-only account is the session family's
`FamilyStartedAt` (looked up via `toa_sid`) or `toa_2fa_at`, inside `LinkProofWindow`. Local tokens
carry no `auth_time`, and adding one would have been a new claim to carry through refresh.

Unlinking takes the same proof and revokes everything, as removing a passkey does: the reason to remove
a provider is usually that somebody else linked it, and nothing records which session it opened.

## Not done

- No profile sync on later sign-ins.
- No per-provider claim mapping; the global `IClaimsProfileMapper` applies.
- No `client_secret_basic` or `private_key_jwt`; `client_secret_post` is accepted by every provider
  named in the issue.
- A trusted device does not skip the second factor after a provider sign-in, as after a magic link.

## Provider-verified addresses (#421)

Schuly found that an account created by a provider sign-in has no `email` claim, since the claim came
only from a verified local credential, and it matches administrators by address. `TrustEmailVerified`
per provider, off by default, because an application granting anything by address grants it to
whoever the provider lets claim one.

What the provider said is recorded on the link row (`Email`, `EmailVerified`) at link time and on every
sign-in where it changed; whether to believe it is decided at token issue from the current
configuration. So the claim is **recomputed** on refresh, as the local verified address already was,
and turning trust off takes effect at the next refresh without touching data. A verified local address
wins; among several trusted links the most recently used one does. The store method's default is a
no-op rather than a throw, because it runs on every provider sign-in and a custom store without it
should keep signing people in, with its links simply never vouching for an address.

Step-up issued its token from the credential directly and now goes through the same lookup, so a
step-up does not drop an address a refresh would carry.
