# Two-factor authentication

TOTP - the six digits an authenticator app shows - on top of local password login, with recovery
codes for the day the phone goes in the river.

```csharp
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);   // section "TwoFactor"

app.MapToamaisutaaTwoFactorEndpoints();
```

No new dependency. RFC 6238 is a keyed hash, a big-endian counter and a modulo, all of which are in
the base class library, so there is no TOTP package here and no QR code renderer either - enrolment
hands you an `otpauth://` URI and your application draws it.

It needs somewhere to actually apply: either `AddToamaisutaaPasswordLogin`, which gives it the
challenge step, or `AddToamaisutaaTwoFactorClaims`, which lets a policy see an enrolment on an
identity provider's token. Registering neither is checked at startup, because otherwise users could
enrol, be handed recovery codes, and never once be challenged.

## The endpoints

| Method | Route | Auth | Answers |
|---|---|---|---|
| GET | `/auth/2fa` | Authenticated | 200 with status |
| POST | `/auth/2fa/begin` | Authenticated | 200 with a secret and an `otpauth://` URI |
| POST | `/auth/2fa/confirm` | Authenticated | 200 with recovery codes, or 400 |
| POST | `/auth/2fa/disable` | Authenticated **and proof** | 204, or 400 |
| POST | `/auth/2fa/recovery-codes` | Authenticated **and proof** | 200 with new codes, or 400 |
| POST | `/auth/2fa/verify` | Anonymous | 200 with a token pair, or 401 |
| POST | `/auth/2fa/step-up` | Authenticated | 200 with a challenge, 400, or 401 |
| POST | `/auth/2fa/step-up/verify` | Authenticated | 200 with a new access token, 400, or 401 |

These are this package's own shapes, so they are camelCase in both directions. `/auth/2fa/verify` is
the exception: it ends a sign-in, so it returns the same RFC 6749 token body as
[`/auth/login`](/password-login#bodies).

### Bodies

**`GET /auth/2fa`**

```json
{ "enabled": false, "enrolmentPending": false, "recoveryCodesRemaining": 0 }
```

**`POST /auth/2fa/begin`** takes no body. Render `uri` as a QR code; show `secret` for anyone typing
it in by hand.

```json
{
  "secret": "Q3POHNNLWL4EYRNJJ6OQ4WTGG5PTYOCU",
  "uri": "otpauth://totp/Example:ada?secret=Q3POHNNLWL4EYRNJJ6OQ4WTGG5PTYOCU&issuer=Example&algorithm=SHA1&digits=6&period=30"
}
```

**`POST /auth/2fa/confirm`** takes `{ "code": "123456" }` and returns the recovery codes, once:

```json
{ "recoveryCodes": ["GT7AX-P26E5", "LTN7X-CHS77", "..."] }
```

**`POST /auth/2fa/disable`** takes `{ "proof": "123456" }` and answers 204 or 400.
**`POST /auth/2fa/recovery-codes`** takes the same and returns the same shape as `confirm`.

**`POST /auth/2fa/verify`** finishes the sign-in. `rememberDevice` and `deviceLabel` are optional and
only meaningful with [trusted devices](/trusted-devices).

```json
{ "challenge": "No1CXq9-...", "code": "123456", "rememberDevice": false, "deviceLabel": null }
```

It answers the token-pair body, or 401 with
`{ "error": "invalid_grant", "error_description": "That code is not valid." }`. Everything else here
answers 400 with `{ "errors": ["..."] }`.

::: tip Confirming logs you out of the token you used to confirm
`confirm`, `disable` and `recovery-codes` each move the user's security stamp, which invalidates the
access token that made the call. The next request answers **401 with `"error": "invalid_token"`** -
refresh and retry rather than reusing it. A client with
[refresh-on-401](/spa#refresh-on-401) already does this and the user notices nothing.
:::

## Step-up

A [freshness policy](/trusted-devices#requiring-a-fresh-factor) answers 403 when the session's last
live second factor is too old - a device-trusted sign-in, or a code entered an hour ago. Step-up is
how the user gets past it without signing out.

```
POST /auth/2fa/step-up          authenticated, no body   → 200 with a challenge
POST /auth/2fa/step-up/verify   authenticated            → 200 with a new access token
```

```json
// POST /auth/2fa/step-up          →
{ "challenge": "No1CXq9-...", "expires_in": 300 }

// POST /auth/2fa/step-up/verify   { "challenge": "No1CXq9-...", "code": "123456" }   →
{ "access_token": "eyJ...", "expires_in": 900, "token_type": "Bearer", "recovery_codes_running_low": null }
```

**No refresh token comes back, and none is needed.** Your existing one keeps working; replace only
the access token. Rotating the family here would mean a client that ignored a new refresh token
presented a spent one at its next refresh, tripping reuse detection - so proving your identity would
end every session you have.

### What it changes

| | Before a step-up | After |
|---|---|---|
| `toa_2fa_at` | when the factor was last presented | now |
| `toa_2fa_source` | `device`, or the original factor | `otp` or `recovery` |
| `amr` | `["pwd","mfa"]` | `["pwd","mfa","otp"]` |

`amr` only ever grows. A session that signed in on a trusted device carries no `otp`, and after a
live TOTP step-up it does - so a policy written as `RequireClaim("amr", "otp")` starts passing
rather than the user who just did the most work being the one it refuses. Nothing is ever removed,
so no policy that passed before a step-up can start failing after one.

A recovery code adds only `mfa`, matching what a recovery *sign-in* records - RFC 8176 has no
`recovery` value and this package does not invent claim values. Which factor it actually was lives
in `toa_2fa_source`.

### What it does not change

**The security stamp stays put.** Bumping it would revoke the refresh family of the session being
elevated, so proving you are yourself would sign you out.

### Things worth knowing before you wire it up

- **A trusted device cannot satisfy a step-up.** There is no device token field on either endpoint -
  a cached factor is exactly what step-up exists to refuse, so the way it is refused is that there
  is nothing to present.
- **A recovery code can, and it un-trusts every device.** Same inference as at sign-in: the
  authenticator is gone. That does not change based on which endpoint it was typed into.
- **Wrong codes count toward lockout.** Somebody holding a stolen access token can lock the owner
  out of step-up, and that is the right trade - the alternative is handing that same person an
  unthrottled six-digit oracle. The user keeps ordinary access for the life of the token they hold
  and loses step-up for the lockout window.
- **A signed-out session cannot step up**, even while its access token is still inside its lifetime.
- **Identity-provider sessions cannot step up.** 400, not 401, naming the limitation: this package
  cannot mint a replacement for a token it did not issue. Same boundary as everywhere else.

## Enrolment is two steps, on purpose

`begin` generates a secret and stores it **unconfirmed**. Nothing is enabled. `confirm` takes a
working code, and only then is the second factor on.

One step would mean that anyone who opened the settings page, generated a secret and closed the tab
without scanning anything would be locked out of their own account with no way back in. The
ceremony exists so that the account is never protected by a secret nobody has proved they hold.

Calling `begin` twice replaces the first secret, which is correct - and does mean that someone who
scanned the first QR code and then reloaded the page is holding a dead one. `confirm` cannot tell a
wrong code from a stale one, because the superseded secret is gone and there is nothing left to check
against, but it can tell that the row was rewritten, and says so.

## Signing in becomes two steps too

`/auth/login` gains a second success shape. For an enrolled user it returns **200 with a challenge
and no tokens**:

```json
{ "two_factor_required": true, "challenge": "No1CXq9-...", "expires_in": 300 }
```

Present that with a code to `/auth/2fa/verify` and you get the usual token pair back. The code field
takes a TOTP code or a recovery code - one field, because the person typing it should not have to
tell you which kind they are holding when the shape already says.

::: warning Breaking change
Existing clients that assume `/auth/login` returns tokens will break the moment a user enrols. This
is why it is a status shape rather than a new status code: the branch is explicit and cannot be
missed by a client that only checks for 200.
:::

### The challenge is not a token

It is 32 random bytes, stored as a SHA-256 hash, single-use, and valid for five minutes. It is not a
JWT and carries no claims, so it cannot be presented as a bearer token to your API - an ordinary
endpoint returns 401 no matter how your validation is configured. Treat it as a credential in
transit: it is worth exactly one sign-in to whoever holds it.

## Recovery codes

Ten of them, shown exactly once, stored as unsalted SHA-256 - the same reasoning as refresh tokens:
these are high-entropy random values, so there is no dictionary to defend against and nothing for a
salt to do.

Each is single-use. Regenerating invalidates every previous one, because otherwise a printout that
leaked stays good forever. When few remain, a redemption sets `recovery_codes_running_low` on the
response so your application can prompt before somebody runs out and needs a support ticket.

Hyphens, spaces and case are ignored when a code is typed back.

## Replay protection

A code is accepted only if its time step is strictly newer than the last one accepted. Without that,
an observed code stays usable for the rest of its drift window - ninety seconds at the default - and
anything that can see a code once can replay it.

The cost is that the same code cannot be used twice in a row, which matters when scripting: wait for
the next step.

## The secret is encrypted, not hashed

A TOTP secret has to be readable to generate the codes it is checked against, so it is the one value
in this package that cannot be a one-way function. AES-256-GCM, under **its own key**:

```json
{
  "TwoFactor": {
    "EncryptionKey": "<base64, exactly 32 bytes>",
    "EncryptionKeyVersion": "1"
  }
}
```

Use a different key from `LocalLogin:SigningKey`. They do different jobs, they rotate on different
schedules - rotating a signing key signs people out for fifteen minutes, rotating this one means
re-encrypting every enrolment - and a signing key may later need to be asymmetric, which an AES key
cannot be.

Rotate the same way as the pepper - move the old key into `TwoFactor:RetiredEncryptionKeys` under its
version marker, set a new key and version, and rows re-encrypt themselves as people sign in.

### Where the secret is kept is a seam

`ISecretProtector` is what turns a secret into ciphertext and back. The default is AES-256-GCM with
the key from configuration. Replace it to put the key somewhere configuration cannot reach - a key
management service, an HSM, your cloud provider's vault:

```csharp
builder.Services.AddSingleton<ISecretProtector, YourKeyVaultProtector>();
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);
```

`ProtectedSecret` carries a `KeyVersion` alongside the ciphertext, so your implementation can rotate
on the same terms the default does: decrypt anything you have a key for, re-encrypt under the current
one as rows are touched.

`ITotpProvider` and `IRecoveryCodeProvider` are seams for the same reason - generating and checking
the codes, and generating the recovery codes - though there is rarely a reason to move off RFC 6238.
Replace `IRecoveryCodeProvider` if you want a different code format from the `XXXXX-XXXXX` default.

::: danger Lose the key and every enrolled user must enrol again
There is no recovery. A TOTP secret cannot be re-derived from anything, and decryption fails closed
rather than guessing. Keep the retired keys until you are certain no row still references them.
:::

## Enforcement

`TwoFactor:Enforcement` takes three values:

| Value | Means |
|---|---|
| `Optional` | Users may enrol. Nothing is required. The default |
| `RequiredForLocalLogin` | An enrolled user must complete the challenge |
| `RequiredForAll` | Tokens for users who have not enrolled carry `toa_2fa_required` |

Enrolment alone decides whether a sign-in is challenged - somebody who turned it on gets it in every
mode. What the setting governs is who gets pushed into enrolling.

Locally issued tokens carry `amr` (RFC 8176, the standard claim for exactly this):

| Sign-in | `amr` |
|---|---|
| Password only | `["pwd"]` |
| Password plus TOTP | `["pwd", "otp", "mfa"]` |
| Password plus recovery code | `["pwd", "mfa"]` |

`AddToamaisutaaTwoFactor` registers a policy requiring `amr` to contain `mfa`:

```csharp
app.MapGet("/api/sensitive", () => "…").RequireAuthorization("Toamaisutaa.TwoFactor");
```

### For identity-provider sign-ins, this package enforces nothing

Your identity provider owns that exchange, and Toamaisutaa never sees it. There is no point at which
this package could insist on a second factor for a user signing in through Keycloak - if you want
that, configure it there.

What it can do is `AddToamaisutaaTwoFactorClaims`, an opt-in `IClaimsTransformation` that looks up
the local enrolment and adds `amr` to an externally issued token, so the same policy works for both.
It costs a database read per authenticated request, which is why it is off by default.

## What revoking actually does

Enabling, disabling and regenerating recovery codes each move the user's security stamp and revoke
every refresh chain, exactly as a password change does. That ends the session at the next refresh -
**it does not kill access tokens already in circulation.**

The stamp is compared on refresh and wherever `ICurrentUser` resolves a user, both of which already
read the database. It is deliberately not compared on every bearer request, which would cost a read
per request forever.

**The maximum window is `LocalLogin:AccessTokenLifetime`, fifteen minutes by default.** If you need
revocation to be immediate, shorten it and accept the extra refresh traffic.

## Never log the enrolment response

`/auth/2fa/begin` returns the secret in plaintext - as base32, and again inside the URI. It has to;
an authenticator cannot be enrolled without it. That makes it the one response in this package that
is itself a long-lived credential.

Do not log it. Not the value, not the URI, not a truncated prefix, not at Debug. A log line added
while chasing a bug ships to wherever your logs aggregate, outlives every key rotation anyone will
remember to perform, and cannot be recalled - and putting it right means every affected user
enrolling again. The same goes for recovery codes.

Nothing in this package logs either one. Log the user id and what happened.

### The leak is easiest to add by accident in your own pipeline

Nothing here logs the secret, but this package cannot stop what wraps it, and one pattern gets it
wrong reliably: **a mediator or middleware that logs every request and response generically.**

`TwoFactorEnrolmentStarted` carries `Secret` and carries it again inside `Uri`. Put it in a response
DTO of your own - which is the natural thing to do when you are composing this package's data with
your own fields - and a pipeline behaviour that serialises responses will write a live TOTP secret
to your logs without anyone writing a line of code that mentions it.

`TwoFactorEnrolmentCompleted.RecoveryCodes` is the same class of thing.

If you have that kind of behaviour, exclude these two types from it explicitly, and do it before you
wrap them rather than after you find them in a log search.

## Calling `ITwoFactorService` yourself

The endpoints are a convenience. `ITwoFactorService` is public, so an application that routes
everything through its own handlers can skip `MapToamaisutaaTwoFactorEndpoints` and call it directly.

One asymmetry to know before you wrap it: **the enrolment methods throw where the rest return a
result.** `BeginEnrolmentAsync`, `ConfirmEnrolmentAsync` and `RegenerateRecoveryCodesAsync` raise
`TwoFactorEnrolmentException`, while `DisableAsync` returns a `TwoFactorResult` with an `Errors`
list. A handler over the first three needs a `try`/`catch` that a handler over the fourth does not.

The message on that exception is safe to show the caller: they are authenticated and working on
their own account, so it says exactly what is wrong.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `EncryptionKey` | none | Required. Base64, exactly 32 bytes |
| `EncryptionKeyVersion` | `1` | Stamped on every row this key encrypts |
| `RetiredEncryptionKeys` | empty | Superseded keys, so old rows still decrypt |
| `Digits` | `6` | Do not change this |
| `Period` | `00:00:30` | Do not change this |
| `DriftSteps` | `1` | Steps either side accepted, for clock drift |
| `SecretSizeBytes` | `20` | The RFC 4226 recommendation |
| `Issuer` | `Toamaisutaa` | The name the authenticator app shows |
| `RecoveryCodeCount` | `10` | |
| `RecoveryCodeLowWaterMark` | `3` | At or below this, a redemption warns |
| `ChallengeLifetime` | `00:05:00` | |
| `Enforcement` | `Optional` | |
| `EnrolledPolicyName` | `Toamaisutaa.TwoFactor` | |

`Digits` and `Period` are configurable and documented as "do not change these" - anything other than
6 and 30 breaks Google Authenticator. They exist so that somebody with an unusual authenticator does
not have to fork the package, not because anyone should touch them.

## Storage

Three tables, added by the `AddTwoFactor` migration:

| Table | Holds |
|---|---|
| `ToamaisutaaUserTwoFactors` | One enrolment per user: the encrypted secret, its key version, when it was confirmed, and the last accepted time step |
| `ToamaisutaaRecoveryCodes` | Hashed single-use codes |
| `ToamaisutaaTwoFactorChallenges` | Half-finished sign-ins, swept by `AddToamaisutaaTokenCleanup` |

The `MoveSecurityStampToUser` migration ships alongside it and moves `SecurityStamp` from
`ToamaisutaaPasswordCredentials` onto `ToamaisutaaUsers`, copying existing values across. A second
factor belongs to the person, not to one way of proving they are them, and a user provisioned by an
identity provider has no credential row to hang it off.
