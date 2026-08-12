# Phase 6: proposed public API surface, step-up authentication

Nothing implemented yet. Sign this off before I write code.

The brief asks for the surface, the challenge binding, the response type, and how the in-place
refresh update is sequenced against issuing the token. Those are here. First, though, one thing in
the brief that does not work as written, because everything else depends on the answer.

---

## 1. D1 cannot be implemented from an access token, and the fix is a new claim

**D1 says step-up updates "the existing `ToamaisutaaRefreshToken` row for the presented session".
The step-up endpoints are authenticated with an access token, and an access token does not identify
a session.**

`AccessTokenRequest` carries `User`, `Roles`, `AuthenticationMethods`, `TwoFactorEnrolmentRequired`,
`TwoFactorSource` and `SecondFactorAt`. A locally issued token therefore carries `sub`, `toa_stamp`,
`amr`, `toa_2fa_source`, `toa_2fa_at` - and nothing that names the refresh family it came from. From
the token alone the server can find the *user*, and cannot find the *session*.

That breaks three things in the brief at once:

- **D1**, which needs to know which row to update.
- **D3**, which binds a step-up challenge to "the session that requested it".
- The constraint that stepping up session A leaves session B untouched, which the brief asks me to
  confirm "falls out of the design rather than needing code". It does not fall out. Without a
  session identifier the only implementable choices are to update every live family for the user -
  which elevates every session at once, exactly what the constraint forbids - or to guess at the
  most recent one, which is a race with a straight face.

The alternatives to a new claim are all worse. Having the client post its refresh token to the
step-up endpoint means sending a fourteen-day credential to an endpoint that does not rotate it,
for identification only. Deriving the family from the user plus "the newest live one" is wrong the
moment somebody has two browsers open, which is the ordinary case.

### The claim

```
toa_sid   the refresh family id, as a string GUID
```

`FamilyId` rather than the token id, because the family *is* the session: it survives rotation by
construction, so the value is stable for as long as the session is, which is the property a step-up
needs. The token id changes every refresh and would name a row that is already rotated.

**Answering the rule in `CLAUDE.md` before it is asked: recomputed, carried, or dropped?**
**Carried.** It is `stored.FamilyId`, already on the row `RefreshAsync` has in hand, and it must be
identical across every rotation of a family or the session identifier is not one. This is the
easiest of the four claims to answer for and it still gets a named test.

`toa_sid` is also the cleanest answer to **D8**. A token with no `toa_sid` is not a local session,
which is exactly the condition D8 wants to refuse - no issuer sniffing, no comparing `iss` against
configuration.

**This is the decision I most want signed off**, because it is a new claim on every locally issued
token and the brief did not ask for one.

---

## 2. Entities

### `ToamaisutaaTwoFactorChallenge` gains two columns

```csharp
/// SignIn or StepUp. A challenge minted for one is refused by the other's endpoint.
public TwoFactorChallengePurpose Purpose { get; set; }

/// The refresh family that asked for this. Null for SignIn - there is no session yet.
public Guid? FamilyId { get; set; }

public enum TwoFactorChallengePurpose
{
    SignIn,
    StepUp,
}
```

`Purpose` is the discriminator D3 asks for. `FamilyId` is the binding, and it is separate on
purpose: purpose alone stops a step-up challenge being spent at the anonymous sign-in endpoint, and
binding stops one session's step-up challenge being spent by another session of the same user.

Both are needed. Purpose without binding leaves a user with two sessions able to elevate the wrong
one; binding without purpose leaves the cross-endpoint redemption open.

A migration across all four providers. `FamilyId` is a GUID, not an instant, so the converters do
not come into it.

### `ToamaisutaaRefreshToken` gains nothing

`SecondFactorAt` and `TwoFactorSource` already exist. Step-up mutates them rather than adding to
them, which is the whole point of section 3.

---

## 3. The in-place update, and the store change that breaks

### The method

```csharp
// IRefreshTokenStore
/// Moves the live row of a family forward after a step-up. Never called for anything else.
Task<bool> UpdateSecondFactorAsync(
    Guid familyId,
    string twoFactorSource,
    DateTimeOffset secondFactorAt,
    CancellationToken cancellationToken = default);
```

Keyed on **family, not token id**, and it targets the one row in that family with `RotatedAt`,
`RevokedAt` both null. That matters: a client may well have refreshed between receiving its access
token and stepping up, so the row the token was minted alongside is already rotated and the live row
is a different one. Keying on the token id would update a dead row and the freshness would vanish at
the next refresh - the exact bug this phase exists to prevent, reintroduced by the fix for it.

Returns `false` when the family has no live row, which section 6.2 needs.

**Invariant it relies on:** a family has at most one row with neither `RotatedAt` nor `RevokedAt`
set. That holds today by construction - `RefreshAsync` marks the old row rotated before creating the
next - and the implementation should assert rather than assume it.

### This is a breaking change and I would not soften it

Adding a method to `IRefreshTokenStore` breaks every consumer implementing their own store, which
`docs/storage.md` now actively documents as a supported thing. C# would let me ship a default
interface implementation and keep it additive.

**Do not.** A default that does nothing makes a step-up appear to succeed and silently expire one
access-token lifetime later, on a store the consumer wrote themselves, with nothing failing in
between. That is this bug's exact signature, and shipping a default no-op would be building a
factory for it. A default that throws is honest but turns a compile error into a runtime one.

So: no default, PR labelled `breaking`, and the release note says what to add. The version stays
minor under the pre-1.0 resolver.

---

## 4. Endpoints and response types

```
POST /auth/2fa/step-up          authenticated   200 challenge | 400 | 401
POST /auth/2fa/step-up/verify   authenticated   200 access token | 400 | 401 | 429
```

Both under `LocalLogin:EndpointPrefix` + `/2fa`, mapped in the existing group so the
`StaleSecurityStampFilter`, the tags and the name prefix all apply without new wiring.

### Response types

Two new public records, `[JsonPropertyName]` on every field, serialisation tests asserting exact
JSON - the 0.4.0 convention.

```csharp
public sealed record StepUpChallengeResponse
{
    [JsonPropertyName("challenge")]     public required string Challenge { get; init; }
    [JsonPropertyName("expires_in")]    public required int ExpiresIn { get; init; }
}

public sealed record StepUpResponse
{
    [JsonPropertyName("access_token")]  public required string AccessToken { get; init; }
    [JsonPropertyName("expires_in")]    public required int ExpiresIn { get; init; }
    [JsonPropertyName("token_type")]    public string TokenType { get; init; } = "Bearer";

    [JsonPropertyName("recovery_codes_running_low")]
    public bool? RecoveryCodesRunningLow { get; init; }
}
```

**Not `TwoFactorChallengeResponse`** for the first, even though it is nearly the same shape: that
one carries `two_factor_required: true`, which is a lie here. Nothing is required - the caller asked.

**Not `TokenResponse`** for the second, as the brief says, because there is no refresh token. Sharing
it would mean a `refresh_token: null` on every step-up, and a client that stored it would blank the
credential it needs to stay signed in.

snake_case on both, because both are token-endpoint shapes and that is the line already drawn.

`recovery_codes_running_low` carries here for the same reason it carries at sign-in, and it is
`true`-or-absent, matching the existing field exactly.

### Requests

```csharp
public sealed record StepUpVerifyRequest(string Challenge, string Code);
```

camelCase, like every other request. **No device token field**, per D5 - the way a trusted device is
refused is that there is nothing to present, in the same spirit as the challenge being unable to be
a bearer token.

---

## 5. Sequencing

The brief says both writes happen "in the same operation". There is no unit of work spanning
`IRefreshTokenStore` and `IAccessTokenIssuer`, and inventing one would put a transaction abstraction
into `Core` for a single call site. So the ordering is the mitigation, and it is not symmetric:

```
1. Verify the caller's token carries toa_sid            (else 400 - D8)
2. Verify the family is live                            (else 401 - section 6.2)
3. Verify enrolment exists and is confirmed             (else 400 - D9)
4. Verify the account is not locked out                 (else 401 - D6)
5. Redeem the challenge: purpose, binding, code         (else 401, counting toward lockout - D6)
6. If a recovery code was used, revoke trusted devices  (D5)
7. UPDATE the refresh row                               <-- before
8. ISSUE the access token                               <-- after
```

**7 before 8, deliberately.** If the update lands and the issue fails, the user is told step-up
failed and their next refresh carries freshness they did in fact earn - they presented a valid code.
Wasteful, not wrong. If the issue lands and the update fails, the user holds a token claiming
freshness that the refresh row will contradict in fifteen minutes, which is the failure this whole
phase is about. One order fails safe and the other fails exactly the wrong way.

Write it down next to the code, because the natural instinct is to issue first and record after.

---

## 6. Interactions the brief does not cover

These are the ones I went looking for after last phase. Each fails silently.

**6.1 — Step-up is the first in-place mutation of a refresh row.** Everything else in this package
rotates. The comment D1 asks for is necessary but not sufficient; the store method is named
`UpdateSecondFactorAsync` rather than anything generic so that a future caller reaching for it has to
notice what it is for.

**6.2 — A signed-out session can still step up.** `SignOutAsync` revokes the family, but the access
token stays valid until it expires - up to fifteen minutes. Nothing today stops that token calling
step-up. The update would find no live row and, without a check, step-up would issue a fresh access
token for a session the user deliberately ended.

**Refuse it.** No live row for `toa_sid` means 401. This is why `UpdateSecondFactorAsync` returns
`bool` rather than `void`, and it needs a named test - it is the one place where step-up could
resurrect something.

**6.3 — `toa_2fa_source` moving is a second write-once-to-mutable boundary, and D7 is right that it
is easy to miss.** Adding to it: a device-trusted session carries `amr: ["pwd","mfa"]` with **no
`otp`**. After a live TOTP step-up the source becomes `otp` - but `amr` still has no `otp`, because
`amr` is carried on the family and describes how the *session* was established. I think that is
correct and consistent with D7 saying `amr` gains nothing, but it means a stepped-up session reports
`toa_2fa_source: otp` alongside `amr` without `otp`, which reads like a contradiction to anyone who
finds it. Either it is documented as deliberate or `amr` has to move too, and moving it is a bigger
change than this phase wants. **I propose documenting it, and I want this one explicitly signed
off.**

**6.4 — Lockout counters live on the password credential.** D6 says step-up participates in lockout.
`IPasswordCredentialStore` holds those counters, so a user with a locally issued token always has a
credential row to count against - local sign-in cannot happen without one. That holds, but it is an
assumption worth stating, because it is the thing that would break first if local tokens were ever
issued through another route.

**6.5 — A step-up challenge outliving its session.** If the family is revoked between issuing the
challenge and verifying it, 6.2 already refuses at step 2. Listed only so it is clear the ordering
covers it rather than by accident.

**6.6 — Two step-ups in flight for one session.** Both challenges are live, both bound to the same
family; the first redeemed wins and the second is spent-or-expired on its own terms. No new
mechanism, but it is a case somebody will ask about.

---

## 7. The policy helper (D10)

```csharp
// Registered by AddToamaisutaaTwoFactor, alongside the existing Toamaisutaa.TwoFactor policy.
options.AddPolicy("FreshSecondFactor", policy => policy.RequireFreshSecondFactor(TimeSpan.FromMinutes(5)));
```

An extension on `AuthorizationPolicyBuilder`, so it composes with `RequireAuthenticatedUser`,
role requirements and anything else rather than being a policy factory that owns the whole policy.

It parses `toa_2fa_at` as Unix seconds, and a token with the claim absent or unparseable fails
closed. The hand-written version stays in `docs/trusted-devices.md` next to it, per D10.

---

## 8. Test plan

The brief's eleven, plus what falls out of the above:

- `toa_sid` is identical across a refresh, and identical across three refreshes. If it is not, every
  step-up after the first refresh targets nothing.
- A token with no `toa_sid` - simulating an external one - answers 400 at both endpoints.
- **6.2**: sign out, then step up with the still-valid access token → 401, and no new token issued.
- Step up, refresh, assert `toa_2fa_at` did not go backwards. The three-line one.
- Sign in on a trusted device, step up with TOTP, refresh, assert `toa_2fa_source` is `otp` and not
  `device`.
- A step-up challenge at `/auth/2fa/verify` → 401. A sign-in challenge at
  `/auth/2fa/step-up/verify` → 401. A step-up challenge from session B presented by session A → 401.
- Step-up leaves the security stamp untouched and the session alive.
- Session A stepped up leaves session B's `toa_2fa_at` untouched - which is the test that would have
  caught section 1 had I written the code first.
- A recovery code at step-up succeeds and every trusted device is gone afterwards.
- Wrong codes to the lockout threshold, then a correct code refused while locked.
- No enrolment → 400.

Every one mutation-checked, and the specific mutation the brief names - delete the refresh-row update
and confirm it is the freshness test that reddens, not something else wearing its name.

---

## What changed while implementing this

Signed off with one decision reversed and two additions. Plus one thing the mutation pass found
about my own tooling rather than about the code.

### 1. `amr` moves, reversing D7

The false negative decided it: a consumer writing `RequireClaim("amr", "otp")` means "a real second
factor", and under the original D7 a device-trusted user who had just completed a live TOTP step-up
failed that policy - the one user who did the most work. Documenting it as deliberate would not have
stopped it being wrong.

So `amr` is a **monotonic union**: step-up adds to the set and never removes. `["pwd","mfa"]` becomes
`["pwd","mfa","otp"]`. Because it only grows, no policy that passed before a step-up can begin
failing after one, so there is no regression surface. It also dissolves the contradiction section
6.3 asked to have documented rather than explaining it: `amr` is every method this session has used,
`toa_2fa_source` is the most recent one. Two questions, two answers.

**One deviation from the instruction, and it is a real one.** The sign-off said step-up "adds `otp`
or `recovery`". A recovery code adds only `mfa` here. RFC 8176 has no `recovery` value, this package
does not invent claim values, and a recovery *sign-in* already records `["pwd","mfa"]` - so writing
`recovery` into `amr` would have made the same event report differently depending on which endpoint
it happened at. Which factor it actually was is in `toa_2fa_source`, which exists for that question.

### 2. The store gained a second method

`FindLiveByFamilyAsync` alongside `UpdateSecondFactorAsync`, both without defaults. The union in (1)
needs the family's current methods before it can add to them, and the same read answers section
6.2's "is this session still live". One read, two jobs, and computing the union inside the store
would have put policy in a place that should only persist.

### 3. `IssueAsync` computes the family id before the token

It used to be computed inline in the row initialiser. The token has to carry the same value, so it
is a local now. Small, and the one line where `toa_sid` could silently disagree with the row it
names.

### 4. The mutation pass, including one mutation that lied

Six mutations, each checked for *which* tests reddened rather than how many:

| Mutation | Reddened |
|---|---|
| Refresh row never updated | `Stepping_up_survives_a_refresh`, `..._device_trusted_session_replaces_device...` |
| Challenge purpose ignored | `A_step_up_challenge_is_refused_at_the_sign_in_endpoint` |
| Session binding ignored | `A_step_up_challenge_from_another_session_is_refused` |
| `otp` never added / union dropped | `Amr_gains_otp_on_a_step_up_and_loses_nothing` |
| Liveness guard removed | `A_signed_out_session_cannot_step_up` |
| `toa_sid` never written | 12, including both `toa_sid` tests |
| Session-claim guard skipped | `A_token_with_no_session_claim_answers_400` |

Two findings from doing it that way:

**The purpose and binding checks overlap.** A sign-in challenge presented at the step-up endpoint is
refused by binding as well as by purpose, because a sign-in challenge has a null `FamilyId`. So
`A_sign_in_challenge_is_refused_at_the_step_up_endpoint` survives either mutation alone. The
behaviour is doubly covered rather than uncovered, but the test does not isolate what it names.

**One mutation silently did not apply and reported zero failures.** The pattern spanned lines and
the file has CRLF endings, so the replacement matched nothing - and a "0 failures" reading almost
went into the record as a coverage gap in the `amr` union. The check needs its own check: assert the
pattern was found before trusting that the mutation ran.

### 5. Two tests I wrote were worthless until they were not

`A_token_with_no_session_claim_answers_400` originally doctored a real token by editing its last
characters. That breaks the signature, so the request was refused by the bearer pipeline and never
reached the endpoint - a test asserting authentication while claiming to assert step-up. It now
mints a valid token with the same key and no `toa_sid`, which is the shape it was always meant to
be, and the mutation confirms it.

### Verification performed

- **247 tests green** - 201 service, 46 HTTP.
- **All four migration assemblies regenerated together**, two columns each, no instant columns.
- **End to end over HTTP against the sample**: a device-trusted session refused by a real freshness
  policy at 403, stepped up with one code, allowed at 200, and still allowed after a refresh - with
  `toa_sid` and `toa_stamp` unchanged throughout and no `refresh_token` anywhere in the step-up
  response.
- **0 warnings** under `--no-incremental`.

## Open items

1. **`toa_sid` on every locally issued token.** Section 1. A new claim the brief did not ask for,
   and the only way I can see to make D1, D3 and session independence all true at once. If you would
   rather not add a claim, D1 has to change instead - and I do not have a third option.
2. **`IRefreshTokenStore.UpdateSecondFactorAsync` with no default implementation**, and the
   `breaking` label that comes with it. Section 3.
3. **6.3**: a stepped-up device session reporting `toa_2fa_source: otp` with `amr` lacking `otp`.
   Documented as deliberate, or `amr` moves too.
4. **6.2**: refusing step-up on a revoked family. New behaviour the brief does not specify, and I
   think it is required rather than optional.
5. `StepUpChallengeResponse` as its own type rather than reusing `TwoFactorChallengeResponse`.
   Section 4 - a small thing, but it is a new permanent contract and those get justified one at a
   time.
