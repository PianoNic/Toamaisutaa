# Passkeys

A passkey is a key pair the user's device holds and unlocks with a fingerprint, a face or a PIN.
One browser prompt proves both halves: possession of the authenticator, and that the person in
front of it is the one it belongs to.

```csharp
builder.Services.AddToamaisutaaPasskeys(builder.Configuration);   // section "Passkeys"

app.MapToamaisutaaPasskeyEndpoints();
```

```
dotnet add package Toamaisutaa.Passkeys
```

Needs local password login registered, because a passkey sign-in ends in exactly the token pair a
password sign-in does and that is where the issuer lives. Both are checked at startup.

## The one thing to hold on to

**A verified passkey is two factors in one gesture.** It is not a second factor bolted onto a
password - it replaces the password *and* the code after it. That is why a passkey sign-in satisfies
`TwoFactor:Enforcement` on its own, and why nothing asks for a TOTP code afterwards.

## Configuration

```json
{
  "Passkeys": {
    "RelyingPartyId": "example.com",
    "Origins": [ "https://example.com", "http://localhost:5173" ]
  }
}
```

| Setting | Default | |
|---|---|---|
| `RelyingPartyId` | none | The domain a credential is bound to. A bare domain: no scheme, no port, no path |
| `RelyingPartyName` | the id | What the browser's own prompt calls your site |
| `Origins` | none | The full origins a ceremony may come from. Several is normal: the site, staging, and whatever port the client dev server is on |
| `RequireUserVerification` | `true` | The authenticator must verify the user, not merely notice a touch |
| `ChallengeLifetime` | 5 minutes | How long a begun ceremony stays completable |
| `TimeoutMilliseconds` | 60000 | What the browser is told to wait. Advisory; the server's deadline is the one above |
| `MaxCredentialsPerUser` | 10 | 0 for unlimited |
| `EndpointPrefix` | `/passkeys` | Composed onto `LocalLogin:EndpointPrefix` |

::: danger RelyingPartyId is permanent
Every credential is bound to the value in force when it was registered, and a credential cannot be
re-bound. Changing it later does not migrate anyone - it makes every existing passkey stop working,
and there is no way back but registering them again. Pick the registrable domain, not a subdomain,
unless you are certain you will never serve from another one.
:::

## The endpoints

| Method | Route | Who |
|---|---|---|
| `POST` | `/auth/passkeys/register/begin` | Signed in |
| `POST` | `/auth/passkeys/register/complete` | Signed in |
| `POST` | `/auth/passkeys/assertion/begin` | Anyone |
| `POST` | `/auth/passkeys/assertion/complete` | Anyone |
| `GET` | `/auth/passkeys` | Signed in |
| `DELETE` | `/auth/passkeys/{id}` | Signed in |

Both `begin` endpoints answer the same shape:

```json
{
  "challenge": "…",
  "expires_in": 300,
  "options": { "…": "the WebAuthn options, as the specification defines them" }
}
```

`options` goes to the browser. `challenge` is this package's own opaque handle on the ceremony -
**not** the WebAuthn challenge, which is inside `options` - and it comes back on the matching
`complete` call.

## Registering, from a browser

```js
const begin = await (await fetch('/auth/passkeys/register/begin', {
  method: 'POST',
  headers: { Authorization: `Bearer ${accessToken}` },
})).json();

const created = await navigator.credentials.create({
  publicKey: decodeOptions(begin.options),   // base64url -> ArrayBuffer, see below
});

await fetch('/auth/passkeys/register/complete', {
  method: 'POST',
  headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    challenge: begin.challenge,
    id: created.id,
    attestationObject: b64url(created.response.attestationObject),
    clientDataJson: b64url(created.response.clientDataJSON),
    transports: created.response.getTransports?.() ?? [],
    label: 'work laptop',
  }),
});
```

`201` with the credential as the user will see it in their list. Registering changes no credential
the account already has, so the token that called it keeps working.

Every binary field is base64url in both directions. Standard base64 and padding either way are
accepted too, because the encoding happens in whatever your client is written in and they do not
agree.

## Signing in, from a browser

```js
const begin = await (await fetch('/auth/passkeys/assertion/begin', { method: 'POST' })).json();

const assertion = await navigator.credentials.get({ publicKey: decodeOptions(begin.options) });

const tokens = await (await fetch('/auth/passkeys/assertion/complete', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    challenge: begin.challenge,
    id: assertion.id,
    authenticatorData: b64url(assertion.response.authenticatorData),
    clientDataJson: b64url(assertion.response.clientDataJSON),
    signature: b64url(assertion.response.signature),
    userHandle: b64url(assertion.response.userHandle),
  }),
})).json();
```

The response is the body `/auth/login` returns: `access_token`, `refresh_token`, `expires_in`,
`token_type`.

::: tip There is no user name box
`/assertion/begin` takes no identifier. The browser finds a discoverable credential itself and the
assertion says who it belongs to, so the endpoint has nothing that could answer whether an account
exists - and your sign-in page needs no field before the button.

The corollary is that credentials are always registered as discoverable. An authenticator that
cannot store one is refused at registration rather than at the sign-in where it would silently fail
to appear.
:::

## What the token claims

| Claim | Value |
|---|---|
| `amr` | `hwk`, `user`, and `mfa` when the authenticator verified the user |
| `toa_2fa_source` | `passkey`, when it verified the user |
| `toa_2fa_at` | When the assertion happened |

`hwk` and `user` are RFC 8176: proof of possession of a hardware-secured key, and a user-presence
test. `mfa` is the one a policy reads, and it is added only for an assertion the authenticator
actually verified the user for - a PIN or a biometric, rather than a bare touch.

All three are carried on the refresh family, so a rotation replays them. A session established with
a passkey is still a passkey session an hour later.

## Enforcement

`TwoFactor:Enforcement` governs who is pushed into enrolling in TOTP. A verified passkey sign-in
satisfies it outright:

- **`RequiredForLocalLogin`** challenges an enrolled user during a *password* sign-in. A passkey
  sign-in is not one, and it already proved two factors.
- **`RequiredForAll`** puts `toa_2fa_required` on the token of anyone who has not enrolled. A
  verified passkey token does not carry it, so a user whose only second factor is their phone is
  not told to go and set up an authenticator app as well.

An assertion without user verification - only possible with `RequireUserVerification` off - proves
possession alone. It signs in, it carries `hwk user` and no `mfa`, and the enforcement above applies
to it exactly as it does to a password.

## What is stored

Two tables, `ToamaisutaaPasskeyCredentials` and `ToamaisutaaPasskeyChallenges`. Run the migration
after upgrading; see [storage and migrations](/storage).

The credential row holds the public key - public by definition, so unlike a TOTP secret there is
nothing to encrypt - and the authenticator's signature counter. A counter that fails to advance is
how a cloned authenticator gives itself away, and an assertion carrying one is refused.

The challenge row holds the WebAuthn options exactly as they went to the browser. They carry the
challenge, the relying party and the user verification requirement, and every one of those is a rule
the completion step measures the authenticator against - so they are kept here rather than handed to
the client to give back, which would let it mark its own work.

A challenge is spent the moment it is redeemed, whether or not the assertion then verified. A
mistyped six-digit code deserves a second try; an authenticator response is produced by software in
one shot, so a failed one is not a typo.

## Deleting one

`DELETE /auth/passkeys/{id}`, with the id from the list - never the credential id the authenticator
uses. `404` covers both a passkey that does not exist and one belonging to somebody else, so the
endpoint cannot be used to find out which ids are real.

::: warning The last passkey on a passwordless account
Nothing stops a user deleting their only credential. If they have no password either, that is the
moment the account becomes unreachable. Show them what they have left before they confirm.
:::

## Events

| Kind | When |
|---|---|
| `passkey-registered` | A credential was added to an account |
| `passkey-removed` | One was deleted |
| `sign-in-succeeded` | With `twoFactorSource` of `passkey` |

See [audit events](/audit-events) for the sink.
