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
| `RegistrationProofWindow` | 5 minutes | How recently the caller must have presented a second factor for that to stand in for their current password |
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
| `POST` | `/auth/passkeys/second-factor/begin` | Anyone holding a sign-in challenge |
| `POST` | `/auth/passkeys/second-factor/complete` | Anyone holding a sign-in challenge |
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
  headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ currentPassword }),
})).json();

const created = await navigator.credentials.create({
  publicKey: decodeOptions(begin.options),   // the helpers are defined below
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

`201` with the credential as the user will see it in their list, and no `Location` header: there is
no route that serves one credential, and the id in the body is what the delete takes. Registering
changes no credential the account already has, so the token that called it keeps working.

::: warning A bearer token is not enough to register one
`/register/begin` wants proof that the caller holds a credential the account already has -
`currentPassword`, or a session that presented a second factor within `RegistrationProofWindow`.
Otherwise a stolen access token would buy a permanent way in. `400` with `errors` when the proof is
missing or wrong; `/register/complete` asks for nothing further.

**An account with no password** - one an identity provider owns, or one whose only credential is
already a passkey - proves a second factor instead: sign in with a passkey, or complete
`/auth/2fa/step-up`, then register while `toa_2fa_at` is still inside the window.

**An account with a confirmed second factor** has to present it too; the password alone is refused.
Complete `/auth/2fa/step-up`, then register inside the window. Removing a passkey still takes the
password alone.
:::

Every binary field is base64url in both directions; standard base64 and padding are accepted too.
The two helpers the snippets use:

```js
const b64url = buffer => buffer && btoa(String.fromCharCode(...new Uint8Array(buffer)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const bytes = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

// The options arrive as JSON; the browser wants the challenge and the ids as bytes.
const decodeOptions = options => ({
  ...options,
  challenge: bytes(options.challenge),
  ...(options.user && { user: { ...options.user, id: bytes(options.user.id) } }),
  ...(options.excludeCredentials && { excludeCredentials: options.excludeCredentials.map(c => ({ ...c, id: bytes(c.id) })) }),
  ...(options.allowCredentials && { allowCredentials: options.allowCredentials.map(c => ({ ...c, id: bytes(c.id) })) }),
});
```

Browsers that have `PublicKeyCredential.parseCreationOptionsFromJSON` and
`parseRequestOptionsFromJSON` can use those instead of `decodeOptions`.

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

The response is [the token body `/auth/login` returns](/password-login#bodies).

::: tip There is no user name box
`/assertion/begin` takes no identifier. The browser finds a discoverable credential itself and the
assertion says who it belongs to, so your sign-in page needs no field before the button.

Credentials are therefore always registered as discoverable, and an authenticator that cannot store
one is refused at registration.
:::

## A passkey is a second factor

An account with a passkey registered is not signed in by a password alone, or a magic link alone.
Somebody who registered a passkey reasonably believes their account now needs it, and a phished
password or a read mailbox would otherwise still be a whole session.

So `/auth/login` and `/auth/magic-link/verify` answer such an account with a challenge, exactly as
for a TOTP enrolment, and `second_factors` says what can answer it:

```json
{ "two_factor_required": true, "challenge": "No1CXq9-...", "expires_in": 300, "second_factors": ["passkey"] }
```

An account with both lists `["otp", "passkey"]` and may use either. To answer with a passkey:

```ts
const begin = await post("/auth/passkeys/second-factor/begin", { signInChallenge });
const credential = await navigator.credentials.get({
  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options),
});

const tokens = await post("/auth/passkeys/second-factor/complete", {
  signInChallenge,
  assertion: { challenge: begin.challenge, ...assertionFields(credential) },
});
```

The options name only that account's passkeys - whoever holds the challenge already proved the
first factor, so there is nothing to hide - and only one of them is accepted. The token carries the
first factor's `amr` plus `hwk` and `mfa`, and `toa_2fa_source` is `passkey`.

**Step-up still needs a code.** It has no passkey ceremony, so an account whose only second factor is
a passkey is told it has nothing to step up with.

## What the token claims

| Claim | Value |
|---|---|
| `amr` | `hwk`, `user`, and `mfa` when the authenticator verified the user |
| `toa_2fa_source` | `passkey`, when it verified the user |
| `toa_2fa_at` | When the assertion happened |

`hwk` and `user` are RFC 8176: proof of possession of a hardware-secured key, and a user-presence
test. `mfa` is added only when the authenticator verified the user - a PIN or a biometric, rather
than a bare touch. All three are carried on the refresh family, so a rotation keeps them.

## Enforcement

`TwoFactor:Enforcement` governs who is pushed into enrolling in TOTP. A verified passkey sign-in
satisfies it outright:

- **`RequiredForLocalLogin`** challenges an enrolled user during a *password* sign-in. A passkey
  sign-in is not one, and it already proved two factors.
- **`RequiredForAll`** puts `toa_2fa_required` on the token of anyone who has not enrolled. A
  verified passkey token does not carry it.

An assertion without user verification - only possible with `RequireUserVerification` off - proves
possession alone, and the enforcement above applies to it exactly as it does to a password:

- An account with **no** confirmed TOTP enrolment signs in. The token carries `hwk user` and no
  `mfa`, and `toa_2fa_required` appears under `RequiredForAll` as it would on any other first factor.
- An account **with** one is challenged. `/assertion/complete` answers
  [the challenge shape `/auth/login` does](/password-login#bodies), and the code goes to
  `/auth/2fa/verify`. The finished token carries `hwk user otp mfa`: what the authenticator proved,
  replayed off the challenge, plus what the code proved.

Enrolment alone decides that, in every enforcement mode.

## What is stored

Two tables, `ToamaisutaaPasskeyCredentials` and `ToamaisutaaPasskeyChallenges`. Run the migration
after upgrading; see [storage and migrations](/storage).

The credential row holds the public key - public by definition, so unlike a TOTP secret there is
nothing to encrypt - and the authenticator's signature counter. A counter that fails to advance is
how a cloned authenticator gives itself away, and an assertion carrying one is refused.

The challenge row holds the WebAuthn options exactly as they went to the browser, so the completion
step measures the authenticator against what the server sent rather than what the client gives back.

A challenge is spent the moment it is redeemed, whether or not the assertion then verified.

## Deleting one

`DELETE /auth/passkeys/{id}`, with the id from the list - never the credential id the authenticator
uses. `404` covers both a passkey that does not exist and one belonging to somebody else, so the
endpoint cannot be used to find out which ids are real.

It takes proof as registering does - `{ "currentPassword": "..." }` in the body, or a second factor
within `Passkeys:RegistrationProofWindow` - and answers `400` without it. Unlike registering, the
password alone is enough even on an account with a second factor.

Deleting one ends every session on the account, including the one that asked, since nothing records
which session a given key opened. Sign in again afterwards.

### And by a password reset

Setting a password deletes every passkey on the account, wherever it is set from: `/auth/password`,
`/auth/password/reset` and the administrator's `/auth/users/{userId}/password` - alongside the
sessions and the trusted devices, because somebody doing any of those is reacting to another person
having had access.

Say so on the reset screen. Re-registering is one prompt on the device that still holds the
credential.

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
