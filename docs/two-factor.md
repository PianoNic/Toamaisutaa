# Two-factor authentication

TOTP - the six digits an authenticator app shows - on top of local password login, with recovery
codes for the day the phone goes in the river.

```csharp
builder.Services.AddToamaisutaaTwoFactor(builder.Configuration);   // section "TwoFactor"

app.MapToamaisutaaTwoFactorEndpoints();
```

No new dependency, and no QR code renderer: enrolment hands you an `otpauth://` URI and your
application draws it.

::: tip Passkeys are the other way to do this
A [passkey](/passkeys) proves possession and verifies the person in one browser prompt, which is two
factors without a password and without a code after it. TOTP is what to reach for when a passkey is
not an option - an old device, a shared account, a user who will not enrol one - and the two live
side by side.
:::

It needs somewhere to actually apply: either `AddToamaisutaaPasswordLogin`, which gives it the
challenge step, or `AddToamaisutaaTwoFactorClaims`, which lets a policy see an enrolment on an
identity provider's token. Registering neither is checked at startup, because otherwise users could
enrol, be handed recovery codes, and never once be challenged.

## The endpoints

| Method | Route | Auth | Answers |
|---|---|---|---|
| GET | `/auth/2fa` | Authenticated | 200 with status |
| POST | `/auth/2fa/begin` | Authenticated **and proof** | 200 with a secret and an `otpauth://` URI, or 400 |
| POST | `/auth/2fa/confirm` | Authenticated | 200 with recovery codes, 400, or 429 |
| POST | `/auth/2fa/disable` | Authenticated **and proof** | 204, 400, or 429 |
| POST | `/auth/2fa/recovery-codes` | Authenticated **and proof** | 200 with new codes, 400, or 429 |
| POST | `/auth/2fa/verify` | Anonymous | 200 with a token pair, or 401 |
| POST | `/auth/2fa/step-up` | Authenticated | 200 with a challenge, 400, or 401 |
| POST | `/auth/2fa/step-up/verify` | Authenticated | 200 with a new access token, 400, or 401 |

These are camelCase in both directions, except that `/auth/2fa/verify` ends a sign-in and returns
the [RFC 6749 token body](/password-login#bodies) `/auth/login` does.

### Bodies

**`GET /auth/2fa`**

```json
{ "enabled": false, "enrolmentPending": false, "recoveryCodesRemaining": 0 }
```

**`POST /auth/2fa/begin`** wants proof that the caller is the account holder rather than somebody
holding their token: whoever enrols is the only one who can answer the second factor afterwards.
Send the current password:

```json
{ "currentPassword": "correct horse battery staple" }
```

An account with no password - one an identity provider owns, or a passkey-only one - sends no body
and instead needs a sign-in within `TwoFactor:EnrolmentProofWindow` (five minutes by default), read
off the token's `auth_time` or `toa_2fa_at`. A wrong password counts toward the account's lockout.
Many providers leave `auth_time` out of access tokens - see
[the warning on first passwords](/password-login#bodies), which applies here too.

Render `uri` as a QR code; show `secret` for anyone typing it in by hand.

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
the access token.

### What it changes

| | Before a step-up | After |
|---|---|---|
| `toa_2fa_at` | when the factor was last presented | now |
| `toa_2fa_source` | `device`, or the original factor | `otp` or `recovery` |
| `amr` | `["pwd","mfa"]` | `["pwd","mfa","otp"]` |

`amr` only ever grows. A session that signed in on a trusted device carries no `otp`, and after a
live TOTP step-up it does, so a policy written as `RequireClaim("amr", "otp")` starts passing. No
policy that passed before a step-up can start failing after one.

A recovery code adds only `mfa`, matching what a recovery *sign-in* records. Which factor it actually
was lives in `toa_2fa_source`.

### What it does not change

**The security stamp stays put.** Bumping it would revoke the refresh family of the session being
elevated, so proving you are yourself would sign you out.

### Things worth knowing before you wire it up

- **A trusted device cannot satisfy a step-up.** There is no device token field on either endpoint -
  a cached factor is exactly what step-up exists to refuse.
- **A recovery code can, and it un-trusts every device**, exactly as at sign-in: the authenticator is
  gone.
- **Wrong codes count toward lockout.** Somebody holding a stolen access token can lock the owner
  out of step-up for the lockout window; the owner keeps ordinary access for the life of the token
  they hold.
- **A signed-out session cannot step up**, even while its access token is still inside its lifetime.
- **Identity-provider sessions cannot step up.** 400, not 401, naming the limitation: this package
  cannot mint a replacement for a token it did not issue.

## Enrolment is two steps, on purpose

`begin` generates a secret and stores it **unconfirmed**. Nothing is enabled. `confirm` takes a
working code, and only then is the second factor on, so the account is never protected by a secret
nobody has proved they hold.

Calling `begin` twice replaces the first secret, which is correct - and does mean that someone who
scanned the first QR code and then reloaded the page is holding a dead one. `confirm` cannot tell a
wrong code from a stale one, because the superseded secret is gone and there is nothing left to check
against, but it can tell that the row was rewritten, and says so.

## Signing in becomes two steps too

For an enrolled user, `/auth/login` answers 200 with a challenge and no tokens - see
[the two sign-in shapes](/password-login#bodies). Present that with a code to `/auth/2fa/verify` and
you get the usual token pair back. The code field takes a TOTP code or a recovery code - one field,
because the person typing it should not have to tell you which kind they are holding.

### The challenge is not a token

It is 32 random bytes, stored as a SHA-256 hash, single-use, and valid for five minutes. It is not a
JWT and carries no claims, so it cannot be presented as a bearer token to your API - an ordinary
endpoint returns 401 no matter how your validation is configured. Treat it as a credential in
transit: it is worth exactly one sign-in to whoever holds it.

### Wrong codes count toward lockout

A wrong code at `/auth/2fa/verify` counts against the account itself, together with wrong current
passwords, and a locked account is refused there even with the right code. Unlike a wrong password at
sign-in it is not counted per source: only somebody who already has the password can make one. The right password does not clear the
count on its own: only a finished sign-in does. Otherwise somebody holding the password could sign
in again every four guesses and never reach the limit.

A mistyped code does not spend the challenge, so the person typing it can try again without going
back to the password.

The same count covers the proof `/auth/2fa/disable` and `/auth/2fa/recovery-codes` ask for, and all
three code-taking management endpoints (`confirm`, `disable`, `recovery-codes`) sit behind the
per-address rate limiter. The count lives on the password credential; an account without one - owned
by an identity provider, or signing in with a passkey alone - keeps the same count, under the same
`LocalLogin` thresholds, on its two-factor enrolment instead.

### Repeated locks grow

Somebody who has the password could otherwise guess five codes, wait out the fifteen minutes, and
guess five more, indefinitely - about 240 guesses a day, which finds a six-digit code within a year.
So each lock that follows another, with no completed sign-in in between, lasts twice as long as the
last: 15 minutes, 30, an hour, two, up to `LocalLogin:LockoutMaxDuration` (a day by default). After a
few rounds that is five guesses a day. A completed sign-in, or a new password, starts it again from
fifteen minutes.

A lock that is not the first means somebody holding the password is guessing codes. Every lock
publishes an `account-locked-out` [audit event](/audit-events) whose `Strikes` says which one it is,
which is the moment to tell the owner to change their password:

```csharp
internal sealed class TellTheOwner(IUserStore users, YourMailer mailer) : IAuthenticationEventSink
{
    public async Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
    {
        if (authenticationEvent is not AccountLockedOut { SourceOnly: false, Strikes: > 1, UserId: { } userId })
            return;

        if (await users.FindByIdAsync(userId, cancellationToken) is { Email: { } email })
            await mailer.SendPasswordGuessedWarningAsync(email, cancellationToken);
    }
}
```

## Recovery codes

Ten of them, shown exactly once, and stored as an HMAC under a key derived from
`TwoFactor:EncryptionKey`, so a copy of the table alone is not enough to check a guess. Codes hashed
under a retired key, or issued before codes were keyed, are still accepted until the set is
regenerated.

The ones issued before keying are still plain hashes, and a copy of the table still gives them up.
They are the rows with a `HashVersion` of 0, so they can be counted:

```sql
SELECT COUNT(*) FROM "ToamaisutaaRecoveryCodes" WHERE "HashVersion" = 0 AND "ConsumedAt" IS NULL;
```

When that is small enough to ask the people left to regenerate, set
`TwoFactor:AcceptUnkeyedRecoveryCodes` to `false` and delete those rows.

Each is single-use. Regenerating invalidates every previous one, because otherwise a printout that
leaked stays good forever. When few remain, a redemption sets `recovery_codes_running_low` on the
response so your application can prompt before somebody runs out and needs a support ticket.

Hyphens, spaces and case are ignored when a code is typed back.

## Replay protection

A code is accepted only if its time step is strictly newer than the last one accepted. Without that,
an observed code stays usable for the rest of its drift window - ninety seconds at the default.

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

Use a different key from `LocalLogin:SigningKey`: they rotate on different schedules, and a signing
key can be [asymmetric](/token-signing), which an AES key cannot be.

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

`ITotpProvider` and `IRecoveryCodeProvider` are seams too - generating and checking the codes, and
generating the recovery codes. Replace `IRecoveryCodeProvider` if you want a different code format
from the `XXXXX-XXXXX` default.

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

Your identity provider owns that exchange, and Toamaisutaa never sees it. If you want a second factor
for users signing in through Keycloak, configure it there.

What it can do is `AddToamaisutaaTwoFactorClaims`, an opt-in `IClaimsTransformation` that looks up
the local enrolment and adds `toa_2fa_enrolled` to an externally issued token (and `toa_2fa_required`
under `RequiredForAll`). It costs a database read per authenticated request, which is why it is off
by default. It replaces the framework's do-nothing transformation, but not one of your own.

`toa_2fa_enrolled` says the user has enrolled, and nothing about what they presented at this
sign-in, so the `Toamaisutaa.TwoFactor` policy does not accept it: that policy wants `amr=mfa`, and
for a provider sign-in only the provider can put it there. If "has enrolled" is genuinely what you
want to require, say so with a policy of your own:

```csharp
options.AddPolicy("Enrolled", policy => policy.RequireClaim("toa_2fa_enrolled", "true"));
```

## What revoking actually does

Enabling, disabling and regenerating recovery codes each move the user's security stamp and revoke
every refresh chain, exactly as a password change does. The stamp is compared on refresh and wherever
`ICurrentUser` resolves a user, not on every bearer request, so access tokens already issued keep
working [until they expire](/sessions#what-a-revoke-actually-ends).

## Never log the enrolment response

`/auth/2fa/begin` returns the TOTP secret in plaintext, in `secret` and again inside `uri`, and
`confirm` and `recovery-codes` return recovery codes; all of them are long-lived credentials. Do not
log any of them, at any level - nothing in this package does. If a mediator or middleware of yours
logs responses generically, exclude `TwoFactorEnrolmentStarted` and `TwoFactorEnrolmentCompleted`
from it before you wrap them.

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
| `Digits` | `6` | Do not change this - anything but 6 breaks Google Authenticator |
| `Period` | `00:00:30` | Do not change this - anything but 30 seconds breaks Google Authenticator |
| `DriftSteps` | `1` | Steps either side accepted, for clock drift |
| `SecretSizeBytes` | `20` | The RFC 4226 recommendation |
| `Issuer` | `Toamaisutaa` | The name the authenticator app shows |
| `EnrolmentProofWindow` | `00:05:00` | How recent a sign-in must be to enrol without the current password |
| `EnrolmentLifetime` | `00:15:00` | How long a begun enrolment can still be confirmed; past it, begin again for a new secret |
| `RecoveryCodeCount` | `10` | |
| `RecoveryCodeLowWaterMark` | `3` | At or below this, a redemption warns |
| `AcceptUnkeyedRecoveryCodes` | `true` | Whether codes stored before keying are still accepted |
| `ChallengeLifetime` | `00:05:00` | |
| `Enforcement` | `Optional` | |
| `EnrolledPolicyName` | `Toamaisutaa.TwoFactor` | |

## Storage

Three tables, added by the `AddTwoFactor` migration:

| Table | Holds |
|---|---|
| `ToamaisutaaUserTwoFactors` | One enrolment per user: the encrypted secret, its key version, when it was confirmed, and the last accepted time step |
| `ToamaisutaaRecoveryCodes` | Hashed single-use codes |
| `ToamaisutaaTwoFactorChallenges` | Half-finished sign-ins, swept by `AddToamaisutaaTokenCleanup` |
