# Using this from a SPA

Everything a browser client has to get right, in the order it comes up. Written against local
password login; if your identity provider owns sign-in, you want
[OIDC bearer validation](/oidc) instead and most of this page does not apply.

The one thing to fix in your head first: **an access token is short-lived and a refresh token is
not.** Fifteen minutes against fourteen days. Almost every decision below follows from that gap.

## Where to put the tokens

There is no single right answer, and the package deliberately does not choose for you - it returns
tokens in a response body and reads them from a request body, so your application owns the transport.

| | Access token | Refresh token | Device token |
|---|---|---|---|
| **In memory only** | The safe default | Lost on reload | Lost on reload |
| **`HttpOnly` cookie your server sets** | Works | **The safe choice** | **The safe choice** |
| **`localStorage`** | Survivable | Bad | Worst |

The reasoning is the lifetime. An access token in `localStorage` is worth fifteen minutes to whoever
steals it. A **refresh token** there is worth fourteen days, and a **device token** is worth thirty
days of skipped second factors - and any cross-site scripting bug on your origin reads all three.

::: danger The device token is the one to be careful with
It exists to skip a second factor. In `localStorage`, one XSS turns into a permanent bypass of the
2FA you added precisely to survive a stolen password. Set it as `HttpOnly; Secure; SameSite=Strict`
from your own server, or do not offer "remember this device".
:::

Keeping the access token in a JavaScript variable and nothing else is a real option: on reload you
call `/auth/refresh` with the cookie your server holds and you are signed in again before the first
render finishes.

## Signing in has two success shapes

::: danger Read this one even if you skim the rest
`POST /auth/login` returns **200 with tokens** or **200 with a challenge and no tokens**. Same status
code, different bodies, and the second one does not exist until a user enrols in two-factor - after
which it exists forever.

A client that checks `response.ok` and reads `access_token` works perfectly until the first person
turns on 2FA, then breaks for that person only, in production, long after this code was written.
**Branch on `two_factor_required`.**
:::

This is the branch clients get wrong, because it does not exist until somebody enrols in two-factor
and then it exists forever.

```js
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ identifier, password }),
})

if (response.status === 401) {
  // One body for every refusal: wrong password, no such account, locked out.
  // Do not try to tell them apart - the server deliberately will not.
  const { error_description } = await response.json()
  return showError(error_description)
}

const body = await response.json()

if (body.two_factor_required) {
  // 200, but no tokens. Hold the challenge and ask for a code.
  return goToSecondFactor(body.challenge, body.expires_in)
}

signedIn(body)   // access_token, refresh_token, expires_in, token_type
```

Both shapes are 200. A client that checks `response.ok` and reads `access_token` gets `undefined`
the first time any user turns on two-factor, which is a bug that ships long after the code was
written.

::: tip Field names
Request bodies are camelCase. **Sign-in responses are snake_case**, because they are the RFC 6749
names a token endpoint is expected to use. Everything else this package returns is camelCase. See
[the bodies](/password-login#bodies).
:::

### Finishing with a code

`challenge` is worth exactly one sign-in and expires in five minutes. `code` takes a TOTP code or a
recovery code - one field, because the person typing it should not have to tell you which they hold.

```js
const response = await fetch('/auth/2fa/verify', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ challenge, code, rememberDevice, deviceLabel: 'Ada\'s laptop' }),
})

if (response.status === 401) return showError('That code is not valid.')

const body = await response.json()

if (body.device_token) storeDeviceToken(body.device_token)      // see the warning above
if (body.recovery_codes_running_low) promptToRegenerateCodes()

signedIn(body)
```

`recovery_codes_running_low` is `true` or absent, never `false` - test it as truthy.

## Refresh on 401

The access token expires while the user is doing something. Handle it in one place, at the fetch
layer, or you will handle it in forty places badly.

```js
let refreshing = null

async function api(path, init = {}) {
  let response = await fetch(path, withToken(init))
  if (response.status !== 401) return response

  // Single-flight: five requests failing at once must not spend five refresh tokens.
  // The token rotates on every use, so the four losers would present a spent token -
  // which is the theft signal, and it revokes the whole family. Everyone gets signed out.
  refreshing ??= refresh().finally(() => { refreshing = null })

  const ok = await refreshing
  if (!ok) return redirectToLogin()

  return fetch(path, withToken(init))
}
```

**The single-flight is not an optimisation.** Refresh tokens rotate: each one works once, and
presenting an already-rotated token is how this package detects a stolen refresh token. Two parallel
refreshes look exactly like theft, so the family is revoked, every session ends, and every trusted
device goes with it. A dashboard that fires six requests on load will do this on the first expiry.

Refreshing proactively - a timer at `expires_in` minus a minute - is also fine, and does not remove
the need for the 401 path. A laptop that slept through the expiry wakes up with a dead token.

**A 401 does not always mean expired.** Two cases reach the same handler and both are fixed by
refreshing:

| Body | Means |
|---|---|
| `{ "error": "invalid_token", … }` | The token was issued before a credential changed - a password change, a two-factor enrolment. Refresh. |
| Empty | No token, or one the bearer pipeline rejected outright. Refreshing may still work; if it does not, sign in again. |

## Enrolling in two-factor

Four steps, and the third one is the one people miss.

```js
// 1. Generate a secret. Nothing is enabled yet.
const { secret, uri } = await api('/auth/2fa/begin', { method: 'POST' }).then(r => r.json())

// 2. Render `uri` as a QR code, and show `secret` for anyone typing it by hand.
//    The package ships no QR renderer - that would be a graphics dependency.
renderQrCode(uri)

// 3. Confirm with a working code. Only now is the second factor on.
const confirm = await api('/auth/2fa/confirm', {
  method: 'POST',
  body: JSON.stringify({ code }),
})

if (!confirm.ok) {
  const { errors } = await confirm.json()
  return showError(errors[0])
}

// 4. Show the recovery codes. This is the only time they exist in readable form.
const { recoveryCodes } = await confirm.json()
showOnceAndOfferDownload(recoveryCodes)
```

Three things to design around:

**Your access token dies at step 3.** Confirming moves the user's security stamp, which revokes
every session that existed before it - including the one that just called `confirm`. The next
request answers **401 with `"error": "invalid_token"`**, so the refresh-on-401 wrapper above already
handles it and the user notices nothing. If you call these endpoints outside that wrapper, refresh
explicitly. The same is true of disabling two-factor and of regenerating recovery codes.

**Step 4 is the only time.** Recovery codes are stored hashed and cannot be shown again. A user who
closes that dialog has to regenerate to get a new set. Make it hard to close by accident.

**Calling `begin` twice replaces the first secret.** Somebody who scans a QR code, reloads, and scans
again is holding a dead one, and `confirm` cannot tell that from a wrong code. Do not re-issue on
every render of the settings page.

## Remembering a device

`rememberDevice: true` on `/auth/2fa/verify` returns a `device_token` alongside the tokens. Send it
on the next `/auth/login` and the challenge is skipped:

```js
await fetch('/auth/login', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ identifier, password, deviceToken }),
})
```

**The token rotates on every use.** A device-trusted sign-in returns a *new* `device_token` in the
same body - store it and discard the old one. Presenting a spent one revokes the whole device.

```js
if (body.device_token) storeDeviceToken(body.device_token)   // on every sign-in, not just the first
```

Two consequences worth knowing before somebody reports them as bugs:

- **Two tabs signing in at once will lose the device.** Both present the same token, the second
  looks like a replay, and the family is revoked. Refresh tokens behave the same way and it is the
  right trade, but it is a real thing that happens.
- **`device_expires_in` counts down and does not reset.** The thirty days run from when the device
  was first trusted, so a rotated token reports a smaller number each time. That is the absolute
  lifetime being visible, not a bug.

A recovery code never produces a device token. Redeeming one means the authenticator is gone, so it
revokes every trusted device instead.

## Signing out

```js
await fetch('/auth/logout', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ refreshToken }),
})
```

Always 204, whether or not that token existed. It revokes the refresh family and **deliberately
leaves trusted devices alone** - a device surviving a sign-out is the entire point of having trusted
it. Clear the access and refresh tokens on the client; keep the device token.

Access tokens already issued keep working until they expire, up to
`LocalLogin:AccessTokenLifetime`. There is no way to revoke one, by design - checking a revocation
list on every request is a database read this package will not add. Shorten the lifetime if that
window matters to you.

## Configuration the client reads at startup

`GET /api/app` is anonymous and serves the authority, client id, scope and redirect URIs, so your
build stays environment-agnostic. See
[the runtime configuration endpoint](/getting-started#the-runtime-configuration-endpoint) - including
how to serve your own fields from it.

## A checklist

- [ ] Branch on `two_factor_required`, not on the presence of `access_token`.
- [ ] Refresh is single-flight.
- [ ] The refresh token is not in `localStorage`.
- [ ] The device token is not in `localStorage`.
- [ ] The rotated `device_token` is stored on **every** sign-in, not just the first.
- [ ] The access token is refreshed after confirming, disabling, or regenerating recovery codes.
- [ ] Recovery codes are shown once, prominently, and are hard to dismiss by accident.
- [ ] 401 bodies are shown as-is and never interpreted.
