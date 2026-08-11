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

### The challenge is not a JWT

It is 32 random bytes, stored as a SHA-256 hash, single-use, and valid for five minutes.

A signed challenge would be *structurally* a valid bearer token, kept out of your API only by a
validation rule - and rules are configuration a consumer can loosen. An opaque token cannot be
presented as a bearer token at all. The bypass is impossible rather than defended against, which is
a different and better property.

There is still a test asserting that a challenge gets a 401 from an ordinary endpoint. Not because
the design needs one, but because someone in two years may decide to "simplify" this into a JWT.

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

Not `LocalLogin:SigningKey`, for three reasons: a key used to sign and a key used to encrypt should
not be the same bytes; the signing key may one day become an RSA private key for asymmetric
validation, which cannot also be an AES key; and they rotate on completely different schedules.

Rotate the same way as the pepper - move the old key into `TwoFactor:RetiredEncryptionKeys` under its
version marker, set a new key and version, and rows re-encrypt themselves as people sign in.

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
