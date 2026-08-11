# Phase 4: proposed public API surface, TOTP two-factor authentication

Nothing implemented yet. Sign this off before I write code.

Three things in here contradict the brief. The first is the important one.

---

## 1. D4: the challenge should not be a JWT

The brief says: a short-lived signed token, same local key, distinct audience or a marker claim, and
"make absolutely certain the bearer pipeline rejects it for ordinary API access", with a test proving
a challenge token gets 401 from `/api/me`.

I want to make that test impossible to fail instead of writing it.

**Make the challenge an opaque random token**, 32 bytes from `RandomNumberGenerator`, base64url,
stored hashed exactly like refresh and reset tokens. Not a JWT at all.

The bypass class disappears rather than being defended against:

- A JWT challenge is *structurally* a valid bearer token. It is rejected only because some validation
  rule says so - an audience mismatch, or a claim check. Both are configuration-dependent. A consumer
  who sets `Oidc:ValidateAudience` to `false`, which three of the four analysed codebases did, loses
  the audience defence entirely and is left relying on the claim check alone.
- An opaque token cannot be presented as a bearer token at all. It is not a JWT, it carries no
  signature the handler recognises, and `JwtBearerHandler` rejects it before any of our code runs.
  There is no configuration that makes it work.

The only thing a JWT buys is statelessness, and D4 already gives that up: single-use consumption
means a database row either way. So the JWT costs a defended bypass and buys nothing.

I would still write the test - `/api/me` with a challenge token returns 401 - but as a regression
guard on something structurally true rather than as the thing standing between us and a bypass.

**If you want the JWT anyway**, say so and I will implement it with all three defences at once: a
dedicated audience, a `toa_purpose=2fa_challenge` claim, and an explicit rejection in
`OnTokenValidated` that does not depend on audience validation being on.

## 2. D3: what `SecurityStamp` can actually enforce, and what it cannot

Moving it to `ToamaisutaaUser` is right and I have no argument with it. The question the brief leaves
open is what "enforce it" means, and the honest answer has a limit worth stating before you sign off.

A stamp can only be checked where there is already a database read. There are two candidates:

| Where | Cost | Blast radius |
|---|---|---|
| On refresh, and on any endpoint that resolves `ICurrentUser` | Free - the read already happens | Up to one access-token lifetime, 15 minutes by default |
| On every authenticated request | A database read per request, forever | Immediate |

**I recommend the first.** The second is what ASP.NET Identity does with its
`SecurityStampValidationInterval`, and the reason that setting exists is that people found the
per-request cost unacceptable. A 15-minute worst case on a token that was already going to expire is
a reasonable trade, and shortening `AccessTokenLifetime` tightens it for anyone who disagrees.

So, precisely:

- The stamp is embedded in issued access tokens as `toa_stamp`.
- `RefreshAsync` compares it and refuses a chain whose stamp is stale, revoking the family.
- `ICurrentUser.GetOrProvisionAsync` compares it and throws when stale.
- Bumped by: password set, password change, password reset, 2FA enable, 2FA disable, recovery code
  regeneration.
- **Not** enforced on every bearer request. The README says so plainly rather than implying it.

## 3. Replay protection: yes, and it needs a column

The brief asks whether I implement it. I do, because without it a code stays valid for the whole
drift window - 90 seconds at drift 1 - and anything that can observe one code once (a phishing
proxy, a shoulder surf, a shared screen) can replay it.

`LastUsedStep` on the enrolment row. A code is accepted only if its time step is strictly greater
than the last accepted one. One column, one comparison, and it closes the window to a single use.

---

## Abstractions

### Options

```csharp
public sealed class ToamaisutaaTwoFactorOptions          // section "TwoFactor"
{
    // ── Encryption at rest ──

    /// Base64, at least 32 bytes. Required when two-factor is registered. Its own key rather than
    /// LocalLogin:SigningKey - see "The encryption key" below.
    public string? EncryptionKey { get; set; }
    public string EncryptionKeyVersion { get; set; } = "1";
    public IDictionary<string, string> RetiredEncryptionKeys { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

    // ── TOTP ──

    public int Digits { get; set; } = 6;
    public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);
    /// Steps either side accepted, for clock drift. 1 means a 90-second window.
    public int DriftSteps { get; set; } = 1;
    /// Bytes of secret. 20 is the RFC 4226 recommendation and what authenticator apps expect.
    public int SecretSizeBytes { get; set; } = 20;
    /// Shown in the authenticator app. Defaults to the application's name.
    public string? Issuer { get; set; }

    // ── Recovery codes ──

    public int RecoveryCodeCount { get; set; } = 10;
    /// Warn the caller when this many or fewer remain.
    public int RecoveryCodeLowWaterMark { get; set; } = 3;

    // ── Challenge ──

    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    // ── Enforcement ──

    public TwoFactorEnforcement Enforcement { get; set; } = TwoFactorEnforcement.Optional;
    public string EnrolledPolicyName { get; set; } = "Toamaisutaa.TwoFactor";
}

public enum TwoFactorEnforcement
{
    /// Users may enrol. Nothing is enforced.
    Optional,
    /// A local sign-in by an enrolled user must complete the challenge.
    RequiredForLocalLogin,
    /// Every user must be enrolled. Tokens for the unenrolled carry a claim saying so.
    RequiredForAll,
}
```

Note `Digits` and `Period` are configurable but documented as "do not change these" - deviating from
6 and 30 breaks Google Authenticator, exactly as the brief says. They exist because a consumer with a
non-standard authenticator should not have to fork the package, not because anyone should touch them.

### Entities

```csharp
public class ToamaisutaaUserTwoFactor
{
    public Guid UserId { get; set; }              // primary key and foreign key

    // AES-256-GCM. Recoverable by necessity: a TOTP secret has to be usable, so hashing is not an
    // option, which is why it is the first thing here that is encrypted rather than hashed.
    public byte[] SecretCiphertext { get; set; } = default!;
    public byte[] SecretNonce { get; set; } = default!;
    public byte[] SecretTag { get; set; } = default!;
    public string EncryptionKeyVersion { get; set; } = default!;

    /// Null until the enrolment is confirmed with a working code. Presence is what "enabled" means.
    public DateTimeOffset? ConfirmedAt { get; set; }

    /// The last accepted time step. Replay protection: a code must be strictly newer.
    public long? LastUsedStep { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class ToamaisutaaRecoveryCode
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    /// SHA-256, unsalted, for the reason documented on SecureTokens: these are high-entropy random
    /// values, so there is no dictionary to defend against and nothing for a salt to do.
    public string CodeHash { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}

public class ToamaisutaaTwoFactorChallenge
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string TokenHash { get; set; } = default!;   // unique
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
```

`ToamaisutaaUser` gains `SecurityStamp` (moved from `ToamaisutaaPasswordCredential`, not added
fresh - see the migration section).

### Seams

```csharp
public interface ITotpProvider
{
    /// RFC 6238. Returns true when the code matches within the configured drift, and the time step
    /// it matched, so the caller can store it for replay protection.
    bool TryVerify(byte[] secret, string code, DateTimeOffset now, long? lastUsedStep, out long matchedStep);

    /// otpauth://totp/{issuer}:{account}?secret=...&issuer=...&digits=...&period=...
    string BuildUri(byte[] secret, string issuer, string account);
}

public interface IRecoveryCodeProvider
{
    IReadOnlyList<string> Generate(int count);
}

public interface ISecretProtector
{
    ProtectedSecret Protect(byte[] plaintext);
    byte[] Unprotect(ProtectedSecret secret);
}

public sealed record ProtectedSecret(byte[] Ciphertext, byte[] Nonce, byte[] Tag, string KeyVersion);
```

### Stores

```csharp
public interface ITwoFactorStore
{
    Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default);
    Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default);
    Task RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default);
}

public interface IRecoveryCodeStore
{
    Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default);
    Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default);
    Task MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
    Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default);
}

public interface ITwoFactorChallengeStore
{
    Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default);
    Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default);
}
```

`IUserStore` gains one method, and this is a **breaking change to a published interface**:

```csharp
Task UpdateSecurityStampAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default);
```

### Services and DTOs

```csharp
public interface ITwoFactorService
{
    /// Generates a secret and stores it UNCONFIRMED. Does not enable anything.
    Task<TwoFactorEnrolmentStarted> BeginEnrolmentAsync(Guid userId, CancellationToken cancellationToken = default);

    /// Enables it, and only now. Returns the recovery codes, which are shown exactly once.
    Task<TwoFactorEnrolmentCompleted> ConfirmEnrolmentAsync(Guid userId, string code, CancellationToken cancellationToken = default);

    /// Requires a valid TOTP code or a recovery code. An authenticated session alone is not enough.
    Task<TwoFactorResult> DisableAsync(Guid userId, string proof, CancellationToken cancellationToken = default);

    /// Invalidates every previous code. Same proof requirement as disabling.
    Task<TwoFactorEnrolmentCompleted> RegenerateRecoveryCodesAsync(Guid userId, string proof, CancellationToken cancellationToken = default);

    Task<TwoFactorStatus> GetStatusAsync(Guid userId, CancellationToken cancellationToken = default);
}

public sealed record TwoFactorEnrolmentStarted
{
    public required string Secret { get; init; }        // base32, for manual entry
    public required string Uri { get; init; }           // otpauth://, for the application to render
}

public sealed record TwoFactorEnrolmentCompleted
{
    public required IReadOnlyList<string> RecoveryCodes { get; init; }
}

public sealed record TwoFactorStatus(bool Enabled, bool EnrolmentPending, int RecoveryCodesRemaining);

public sealed record TwoFactorResult
{
    public required bool Succeeded { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// Set when a recovery code was spent and few remain. The application prompts to regenerate.
    public bool RecoveryCodesRunningLow { get; init; }
}
```

`SignInResult` gains a challenge, and `SignInOutcome` gains a value:

```csharp
public sealed record SignInResult
{
    public required SignInOutcome Outcome { get; init; }
    public TokenPair? Tokens { get; init; }
    /// Set only when Outcome is TwoFactorRequired. Present it to /auth/2fa/verify.
    public TwoFactorChallenge? Challenge { get; init; }
}

public sealed record TwoFactorChallenge(string Token, int ExpiresIn);

public enum SignInOutcome
{
    // ... existing values unchanged ...
    TwoFactorRequired,
    InvalidTwoFactorCode,
    ChallengeExpired,
    ChallengeAlreadyUsed,
}
```

Requests:

```csharp
public sealed record BeginTwoFactorRequest();                                  // body-less, authenticated
public sealed record ConfirmTwoFactorRequest(string Code);
public sealed record DisableTwoFactorRequest(string Proof);
public sealed record RegenerateRecoveryCodesRequest(string Proof);
public sealed record VerifyTwoFactorRequest(string Challenge, string Code);
```

`VerifyTwoFactorRequest.Code` accepts either a TOTP code or a recovery code. One field, because the
person typing it should not have to tell us which kind they hold - a recovery code is distinguishable
by shape.

---

## The enforcement claim shape

Locally issued tokens carry **`amr`** (RFC 8176, the standard claim for exactly this):

| Sign-in | `amr` |
|---|---|
| Password only, no 2FA enrolled | `["pwd"]` |
| Password plus TOTP | `["pwd", "otp", "mfa"]` |
| Password plus recovery code | `["pwd", "mfa"]` |

Standard rather than invented, so anything that already understands `amr` keeps working.

Under `RequiredForAll`, a token for a user who has not enrolled additionally carries
**`toa_2fa_required=true`**. That is the answer to "how does an application distinguish authenticated
but must enrol from fully authenticated": the enrolment endpoints stay reachable, everything else can
require the policy.

`AddToamaisutaaTwoFactor` registers a policy named by `EnrolledPolicyName`, default
`Toamaisutaa.TwoFactor`, requiring `amr` to contain `mfa`:

```csharp
app.MapGet("/api/sensitive", () => "…").RequireAuthorization("Toamaisutaa.TwoFactor");
```

**For OIDC users the package cannot enforce anything at sign-in**, because the identity provider owns
that exchange and Toamaisutaa never sees it. What it can do is offer an opt-in
`IClaimsTransformation` that looks up the local enrolment and adds `amr`/`toa_2fa_required` to an
externally issued token, so the same policy works for both. It costs a database read per request,
which is why it is opt-in and off by default, and the README says plainly that enforcement for OIDC
users is the application applying a policy - not the package blocking a sign-in it cannot see.

---

## The encryption key

**Its own key**, `TwoFactor:EncryptionKey`, not `LocalLogin:SigningKey`. Three reasons:

1. **Purpose separation is standard.** A key used to sign and a key used to encrypt should not be the
   same bytes.
2. **The signing key may become asymmetric.** The moment another service needs to validate our tokens
   without holding a secret, `SigningKey` becomes an RSA or ECDSA private key - which cannot be an
   AES-256-GCM key. Sharing them now writes a migration into the future for no benefit today.
3. **They rotate on different schedules.** Rotating a signing key invalidates live tokens for fifteen
   minutes. Rotating an encryption key means re-encrypting every enrolment.

Rotation gets the same treatment as the pepper: `EncryptionKeyVersion` is stamped on each row,
`RetiredEncryptionKeys` holds superseded keys so existing rows still decrypt, and a row is
re-encrypted under the current key the next time it is read. Same shadowing bug to avoid - the active
version means nothing when there is no active key.

**Losing the key means every enrolled user must re-enrol.** There is no recovery: the secret is
unrecoverable by design and cannot be re-derived. The README says this at the same volume as the
pepper warning.

---

## Registration and endpoints

```csharp
public static IServiceCollection AddToamaisutaaTwoFactor(this IServiceCollection services, IConfiguration configuration, string sectionName = "TwoFactor");
public static IServiceCollection AddToamaisutaaTwoFactor(this IServiceCollection services, Action<ToamaisutaaTwoFactorOptions> configure);

/// Opt-in, for enforcing the policy on identity-provider sign-ins. One database read per request.
public static IServiceCollection AddToamaisutaaTwoFactorClaims(this IServiceCollection services);

public static IEndpointConventionBuilder MapToamaisutaaTwoFactorEndpoints(this IEndpointRouteBuilder endpoints);
```

| Method | Route | Auth | Answers |
|---|---|---|---|
| GET | `/auth/2fa` | Authenticated | 200 `TwoFactorStatus` |
| POST | `/auth/2fa/begin` | Authenticated | 200 secret + `otpauth://` URI |
| POST | `/auth/2fa/confirm` | Authenticated | 200 recovery codes, or 400 |
| POST | `/auth/2fa/disable` | Authenticated + proof | 204, or 400 |
| POST | `/auth/2fa/recovery-codes` | Authenticated + proof | 200 new codes, or 400 |
| POST | `/auth/2fa/verify` | **Anonymous**, challenge in body | 200 `TokenPair`, or 401 |

`/auth/2fa/verify` is anonymous because the caller has no token yet - the challenge is the
credential. It is rate-limited by the same limiter as `/auth/login`, and its failures count toward
the same lockout counters, per D4.

`/auth/login` gains a second success shape: when the user is enrolled and enforcement applies, it
returns 200 with a challenge and no tokens. Existing clients that assume tokens will break - that is
in the breaking-changes list, and it is why the shape is `Outcome` plus nullable fields rather than a
new status code.

---

## Migration and breaking changes

Two migrations per provider, four providers, all regenerated together:

1. **`MoveSecurityStampToUser`** - adds `SecurityStamp` to `ToamaisutaaUsers`, copies existing values
   across from `ToamaisutaaPasswordCredentials` with an `UPDATE … FROM` (hand-written per provider,
   as the timestamp conversion was), then drops the old column. Verified against a populated database
   on all four providers before it ships.
2. **`AddTwoFactor`** - the three new tables. Purely additive.

Breaking changes for the release notes:

- `IUserStore.UpdateSecurityStampAsync` added. Any external implementer must add it.
- `ToamaisutaaPasswordCredential.SecurityStamp` removed; `ToamaisutaaUser.SecurityStamp` added.
- `/auth/login` may return a challenge instead of tokens.
- `SignInResult.Challenge` added, `SignInOutcome` gains four values.

Version bump is minor per the pre-1.0 resolver, and the PR is labelled `breaking` so it lands under
⚠️ Breaking Changes.

---

## Test plan

The brief's list, plus what I would want anyway:

- **RFC 6238 test vectors.** The published SHA-1 vectors at the specified timestamps, so the
  implementation is not self-consistently wrong.
- Drift: a code from the previous and next step accepted at `DriftSteps = 1`, rejected at `0`.
- Replay: a code accepted once, then rejected on immediate reuse.
- A challenge token rejected by `/api/me` - a regression guard, given the opaque design makes it
  structurally true.
- A challenge rejected on second use, and after expiry.
- Recovery codes single-use; the low-water-mark flag set when few remain; regeneration invalidating
  every previous code.
- Lockout counting 2FA failures alongside password failures.
- Enrolment not enabled until confirmed - `BeginEnrolmentAsync` alone leaves sign-in unchanged.
- `SecurityStamp` bumped by each of the six operations, and a stale stamp refused on refresh.
- Secret round-trips through `ISecretProtector`; a retired key still decrypts; a missing key fails
  closed.

---

## Open items

1. **The challenge token: opaque, as I recommend, or the signed JWT the brief specifies.**
2. **`SecurityStamp` enforcement points** - refresh and `ICurrentUser` only, as recommended, or
   per-request with the database cost.
3. `Digits` and `Period` configurable at all, or fixed at 6 and 30 with no knob to get wrong.
4. Whether `AddToamaisutaaTwoFactor` implies `AddToamaisutaaPasswordLogin`. It does not have to - 2FA
   on top of OIDC-only is a supported shape - but the challenge flow is meaningless without local
   login, so the startup check should probably require one of the two rather than both.

---

## Sign-off

All four resolved.

1. **Opaque challenge.** The regression test is kept anyway - not because the design needs it, but so
   that someone who later "simplifies" the challenge into a JWT trips a test named for the bypass.
2. **Refresh and `ICurrentUser` only**, with the window stated plainly in the README rather than
   implied.
3. **Configurable, with the XML doc doing the work.** Removing a knob to prevent misuse is the kind of
   paternalism that ends in someone vendoring the source.
4. **One of the two, not both.** And the startup check names the combination the consumer actually
   has: "two-factor registered without password login or the claims transformation" is a feature
   registered that will never fire, which is a confusing enough state to deserve maximum specificity
   and no voice at all.

### The enrolment response is the one secret this package hands out

`TwoFactorEnrolmentStarted.Secret` is base32 plaintext and `Uri` contains the same bytes. Both are the
credential itself, in a response body. Enrolment cannot work any other way, but it makes
`/auth/2fa/begin` the single endpoint in the package that returns a long-lived secret. Three rules
follow:

- **Never log that response.** Written into `CLAUDE.md` beside the personality rule, because a
  well-meaning debug log of an enrolment response writes permanent TOTP secrets into log aggregation,
  where they outlive every rotation anyone will remember to perform.
- **`/auth/2fa/begin` is rate-limited.** Not against brute force - there is nothing to guess - but
  because each call generates and stores a fresh unconfirmed secret, so an unbounded loop is write
  amplification.
- **Calling `begin` twice overwrites the first secret**, which is correct and also means a user who
  scans a QR code and then reloads the page is holding a dead secret. We cannot tell a wrong code from
  a stale one - the old secret is gone, so there is nothing left to check it against - but we can tell
  that *a* secret was superseded, because an unconfirmed row that has been rewritten has
  `UpdatedAt > CreatedAt`. When that is true, the confirm failure adds "if you scanned an earlier QR
  code, scan the current one". No column, no stored superseded secret, and it is honest about being a
  hint rather than a diagnosis.

### Disabling while a challenge is outstanding

Disabling requires proof, so an attacker cannot do it mid-challenge - but a user can, from a second
device, while a challenge sits unconsumed on the first. The row survives and still points at a real
user. **Verification checks that the enrolment still exists**, not merely that the challenge is
unconsumed and unexpired, so a challenge cannot outlive the thing it was challenging.

---

## What changed while implementing this

Six deviations from the signed-off surface. Four are things the proposal simply did not think about;
two are shapes that turned out to be wrong once there was code on the other side of them.

### 1. `IAccessTokenIssuer.IssueAsync` takes a record now

Proposed: unchanged. Actual: `IssueAsync(AccessTokenRequest, CancellationToken)`.

A token has to carry `amr`, `toa_stamp` and `toa_2fa_required`, none of which the old
`(user, roles)` signature had room for. Widening it would have been the second breaking change to
this interface in two releases, and the next thing a token needs to carry would be the third. A
record makes every future addition a property rather than a break.

### 2. `ToamaisutaaRefreshToken` gained two columns

Proposed: three new tables, plus the stamp moving. Actual: also `SecurityStamp` and
`AuthenticationMethods` on `ToamaisutaaRefreshTokens`.

Both fell out of writing the refresh path:

- **`SecurityStamp`** - "refuse a chain whose stamp is stale" needs the stamp as it stood when the
  chain was minted. There is nothing to compare against without it.
- **`AuthenticationMethods`** - without it, a token rotated out of a second-factor session comes back
  carrying `["pwd"]`, and any policy requiring `mfa` starts failing fifteen minutes after a
  successful sign-in. Carried on the family so that a refresh cannot quietly downgrade what a session
  proved.

Both are in `MoveSecurityStampToUser` and are backfilled, so live sessions survive the upgrade.

### 3. Two seam methods the proposal missed

`ITotpProvider.Encode` and `IRecoveryCodeProvider.LooksLikeRecoveryCode`. The first is needed because
`BeginEnrolmentAsync` returns base32 for manual entry and nothing else could produce it; the second
because one input field accepting either kind of code has to decide which it is holding, and that
decision belongs to whatever generates the codes.

`ISecretProtector.NeedsRewrap` likewise: lazy rotation needs to ask.

### 4. `TwoFactorGate`, and why it resolves through the provider

`PasswordSignInService` has to ask "does this user need a second factor" on every sign-in - but
password login works perfectly well with no second factor registered at all. A constructor
dependency would turn "did not call `AddToamaisutaaTwoFactor`" into an unresolvable-service crash at
the first login rather than a supported configuration.

So `TwoFactorGate` is registered by password login and looks its collaborators up through
`IServiceProvider`. Absent, every method answers "no". It is the one place in the package that
resolves a service at call time, and the alternative was worse.

### 5. `TwoFactorEnrolmentException` lives in `Abstractions`, not `Core`

It is thrown across a published interface and caught by the endpoints, so it belongs beside
`ITwoFactorService` rather than beside its thrower.

### 6. The confirm-failure hint is free

The sign-off asked whether we could distinguish "wrong code" from "you scanned an older secret". We
cannot - the superseded secret is gone. But an unconfirmed row that has been rewritten has
`UpdatedAt > CreatedAt`, which is already stored, so the hint costs nothing: no column, no retained
secret, and it is phrased as a possibility rather than a diagnosis.

### Verification performed

- **169 tests green**, including the RFC 6238 published vectors at all six timestamps, drift,
  replay, single-use challenges and recovery codes, key rotation, and fail-closed decryption.
- **All four providers migrated against a populated database.** Seeded a user with a credential and
  one without, applied both migrations, and confirmed the stamp survived on the first, that the
  second got a fresh one rather than an empty string, that the live refresh token's stamp matched and
  its methods were backfilled, that the old column was gone and that all eight tables were present.
  Postgres 18.3, SQLite, SQL Server 2022 and MySQL 8.4.
- **End to end against the sample over HTTP**: enrolment, a two-step login, `amr` coming back as
  `["pwd","otp","mfa"]` for a code and `["pwd","mfa"]` for a recovery code, a policy-protected
  endpoint going 403 → 200, a spent challenge and a spent recovery code both refused, disablement,
  and the old refresh chain dying because the stamp moved.
- **The challenge token presented as a bearer token to `/api/me` returned 401**, as it structurally
  must.
- **The sample's log contains no trace** of the secret, the URI, or any recovery code.

### One thing worth knowing

EF Core's SQLite provider implements `DropColumn` as a table rebuild, which cannot run inside a
transaction, so applying `MoveSecurityStampToUser` on SQLite logs a warning that an interrupted
migration would need reverting by hand. That is inherent to dropping a column on SQLite rather than
anything about this migration, and the data copy runs before the drop, so an interruption loses
nothing that was not already copied.
