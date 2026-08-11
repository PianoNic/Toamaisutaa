# Phase 5: proposed public API surface, trusted devices

Nothing implemented yet. Sign this off before I write code.

The brief asked for three things up front: which operations actually bump `SecurityStamp`, the `amr`
shape, and the metadata decision. Those are first. Then the surface, then four interactions the brief
does not cover that fail the same silent way.

---

## 1. D4 verified, not assumed

I read every call site of `UpdateSecurityStampAsync`. **Five of the eight revoke for free under D3.
Three do not.**

| D4 item | Bumps the stamp today? | Where |
|---|---|---|
| Password change | **Yes** | `PasswordAccountService.SetPasswordAsync` |
| Password reset | **Yes** | `PasswordAccountService.ResetPasswordAsync` |
| 2FA enrolment confirmed | **Yes** | `TwoFactorService.ConfirmEnrolmentAsync` |
| 2FA disabled | **Yes** | `TwoFactorService.DisableAsync` |
| Recovery codes regenerated | **Yes** | `TwoFactorService.RegenerateRecoveryCodesAsync` |
| **Recovery code redeemed** | **No** | `TwoFactorVerifier.RedeemRecoveryCodeAsync` marks the code consumed and nothing else |
| **Refresh token reuse detected** | **No** | `PasswordSignInService.RefreshAsync` revokes the family only |
| **Explicit revoke by the user** | n/a | Does not exist yet |

The two "No" rows are the interesting ones, and they differ:

**Recovery code redeemed — do not bump the stamp.** Bumping it here would revoke the refresh family
of the session being established, which means redeeming a recovery code would sign the user out
mid-sign-in. The trust revocation has to be explicit and scoped to devices only. This is exactly the
case the brief names as most important - a recovery code means the device is gone - and it is the one
place where D3 does not cover it.

**Refresh token reuse — do not bump the stamp either**, for a subtler reason: reuse is detected on a
chain, and the user may legitimately hold other live sessions. Revoking those is arguably right but
is a behaviour change to Phase 3 that is not in scope. Revoke device trusts explicitly, leave the
stamp alone, and say so.

So: **D3 covers five, and two need an explicit `IDeviceTrustStore.RevokeAllForUserAsync` call** at
those two sites, plus the new user-initiated revocation. Three explicit calls, each tested by name.

### The revocation that must NOT cascade

`SignOutAsync` revokes the refresh family and does **not** touch device trust. Signing out is not a
security event, and "remember this device" surviving a sign-out is the entire feature. Listed here
because it is the one place where the obvious reading of "revoke everything" is wrong.

---

## 2. D5: the `amr` shape

`amr` stays honest and standard. A cached second factor still satisfies `mfa` - it was performed,
just not now - so:

| Sign-in | `amr` | `toa_2fa_source` | `toa_2fa_at` |
|---|---|---|---|
| Password only | `["pwd"]` | absent | absent |
| Password + TOTP | `["pwd","otp","mfa"]` | `otp` | now |
| Password + recovery code | `["pwd","mfa"]` | `recovery` | now |
| **Password + trusted device** | `["pwd","mfa"]` | `device` | **the original live challenge** |

No `otp` for a device-trusted sign-in, per D5.

**`toa_2fa_source`** answers "was this cached", which is the minimum the brief asks for.

**`toa_2fa_at` is the addition I want**, and it is what actually makes step-up expressible. Unix
seconds of the last *live* second factor, carried on the device family so a device-trusted token
reports the original challenge rather than now. With it, a step-up policy is:

```
now - toa_2fa_at < 300
```

Without it, "fresh" can only mean "not from a device" - which is cruder and wrong: a live TOTP from
twenty minutes ago is not fresh either, and that policy would accept it. One claim and one column,
and it means step-up never needs another token-shape change.

Not `auth_time`, which is standard but means first-factor authentication time; backdating it to a
second-factor event would be a lie a consumer might act on.

**If you want less, drop `toa_2fa_at` and keep `toa_2fa_source`.** The feature works either way.

---

## 3. D7: what to store

**No user-agent parsing.** Deriving "Firefox on Windows" means either a dependency or a lookup table
that rots. Store the raw string truncated to 256 characters, and let the application supply a label
if it wants something human. One less thing to maintain and no dependency.

```csharp
public string? Label { get; set; }        // application-supplied, optional
public string? UserAgent { get; set; }    // raw, truncated to 256
public string? IpAddress { get; set; }    // null unless configured, see below
```

**IP addresses: three positions, not a boolean.**

```csharp
public IpAddressStorage IpAddressStorage { get; set; } = IpAddressStorage.None;

public enum IpAddressStorage
{
    None,       // default. The column stays null
    Truncated,  // IPv4 /24, IPv6 /48 - "a different network", not "a person"
    Full,
}
```

A boolean forces a choice between nothing and a precise personal identifier. `Truncated` gives a
consumer who wants "this looks like a new network" the signal without the liability, and it is what I
would pick. Deviation from the brief's "configuration flag" and worth a word if you disagree.

The README says what enabling either non-default position means for a privacy notice, at the same
volume as the pepper warning.

---

## 4. Entity

```csharp
public class ToamaisutaaTrustedDevice
{
    public Guid Id { get; set; }

    /// Stable across rotations. This is the "device" a user sees and revokes.
    public Guid FamilyId { get; set; }

    public Guid UserId { get; set; }

    /// SHA-256, unsalted, unique. Same reasoning as every other opaque token here.
    public string TokenHash { get; set; } = default!;

    /// D3. The user's stamp when this family was established. Compared on every use.
    public string SecurityStamp { get; set; } = default!;

    /// The last LIVE second factor on this family. Becomes toa_2fa_at. Not moved by rotation.
    public DateTimeOffset SecondFactorAt { get; set; }

    public string? Label { get; set; }
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// D6. Rotation does not move this, so a weekly-used device still expires.
    public DateTimeOffset FamilyStartedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }
    public DateTimeOffset? RotatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
}
```

`FamilyId` is the public device identifier, not `Id`: `Id` changes on every rotation, so a list
endpoint keyed on it would hand out identifiers that stop working after the next sign-in.

---

## 5. Options

```csharp
public sealed class ToamaisutaaTrustedDeviceOptions          // section "TrustedDevices"
{
    /// Absolute, from FamilyStartedAt. Rotation does not extend it.
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(30);

    /// 0 means unlimited. Oldest family is revoked when the cap is exceeded.
    public int MaxDevicesPerUser { get; set; } = 10;

    public IpAddressStorage IpAddressStorage { get; set; } = IpAddressStorage.None;

    public string EndpointPrefix { get; set; } = "/auth/devices";
}
```

`MaxDevicesPerUser` is not in the brief. Without it the table grows one family per sign-in from a new
browser, forever, and each one is a live 2FA bypass for thirty days. A cap with oldest-out is the
cheapest fix; say if you would rather have none.

---

## 6. Seams and stores

```csharp
public interface ITrustedDeviceService
{
    Task<IReadOnlyList<TrustedDeviceSummary>> ListAsync(Guid userId, CancellationToken ct = default);
    Task<bool> RevokeAsync(Guid userId, Guid deviceId, CancellationToken ct = default);
    Task<int> RevokeAllAsync(Guid userId, CancellationToken ct = default);
}

public sealed record TrustedDeviceSummary
{
    public required Guid Id { get; init; }              // the family id
    public string? Label { get; init; }
    public string? UserAgent { get; init; }
    public string? IpAddress { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset LastUsedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }

    /// True for the device making the request, so a UI can say "this device".
    public required bool IsCurrent { get; init; }
}

public interface ITrustedDeviceStore
{
    Task<ToamaisutaaTrustedDevice?> FindByHashAsync(string tokenHash, CancellationToken ct = default);
    Task<IReadOnlyList<ToamaisutaaTrustedDevice>> ListActiveAsync(Guid userId, CancellationToken ct = default);
    Task CreateAsync(ToamaisutaaTrustedDevice device, CancellationToken ct = default);
    Task MarkRotatedAsync(Guid deviceId, DateTimeOffset rotatedAt, CancellationToken ct = default);
    Task RevokeFamilyAsync(Guid familyId, string reason, DateTimeOffset revokedAt, CancellationToken ct = default);
    Task<int> RevokeAllForUserAsync(Guid userId, string reason, DateTimeOffset revokedAt, CancellationToken ct = default);
    Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken ct = default);
}
```

---

## 7. Requests, results, endpoints

```csharp
public sealed record LoginRequest(string Identifier, string Password, string? DeviceToken = null);
public sealed record VerifyTwoFactorRequest(string Challenge, string Code, bool RememberDevice = false, string? DeviceLabel = null);

public sealed record SignInResult
{
    // ... existing ...
    /// Set only when the caller asked to be remembered and the factor was live.
    public TrustedDeviceToken? TrustedDevice { get; init; }
}

public sealed record TrustedDeviceToken(string Token, int ExpiresIn);
```

| Method | Route | Auth | Answers |
|---|---|---|---|
| GET | `/auth/devices` | Authenticated | 200, the list |
| DELETE | `/auth/devices/{id}` | Authenticated | 204, or 404 |
| DELETE | `/auth/devices` | Authenticated | 204 |

All three rate-limited by the existing limiter, per the constraints.

`/auth/login` gains an optional `deviceToken`. When it validates, the response is the ordinary token
pair - no challenge - and a **rotated** device token.

---

## 8. Four interactions the brief does not cover

These are the ones I went looking for after the `AuthenticationMethods` lesson. Each fails silently
in the unsafe direction.

**8.1 — A device token must never be issued from a device-trusted sign-in.**

If it were, the loop is: present device token → skip challenge → receive a fresh device token. If
that reset `FamilyStartedAt`, D6's absolute lifetime would never be reached and "30 days" would mean
"forever, as long as you sign in monthly". Rotation preserves `FamilyStartedAt` and `SecondFactorAt`;
only a **live** challenge starts a new family. Named test.

**8.2 — Two tabs racing on the same device token.**

Rotation plus reuse detection means the second request sees `RotatedAt` set and revokes the family,
so a user with two tabs open loses the device. Refresh tokens already behave this way and it is the
right trade, but it is worth knowing before someone reports it as a bug. Documented, not fixed.

**8.3 — A device token for a user who is no longer enrolled.**

Disabling 2FA bumps the stamp, so D3 already rejects it. But the row survives until the sweep, and
`ListAsync` would show a device that does nothing. Reject, delete, continue - the same path as a
stamp mismatch.

**8.4 — Lockout is checked before the device token, not after.**

D8 says a trusted device does not bypass lockout. Concretely that means the lockout check stays
where it is in `SignInAsync`, before any device logic, and the device token is consulted only after
the password has been verified. Stated because the tempting optimisation - check the device first
and skip the password derivation - is a lockout bypass and a way to probe which devices are trusted.

---

## 9. Backward compatibility

**The HTTP surface is additive.** `deviceToken` and `rememberDevice` are optional; existing clients
that send neither behave exactly as they do on 0.2.0. `SignInResult` gains a nullable field.

**One .NET break**, and I would take it deliberately:

`IPasswordSignInService.SignInAsync` needs the device token. Options are an optional parameter -
source-compatible for callers, still binary-breaking, and the third signature widening in three
phases - or a request record now. **I propose the record**, for the reason you accepted for
`AccessTokenRequest`: a second widening in three releases is a pattern, not an incident.

```csharp
Task<SignInResult> SignInAsync(PasswordSignInRequest request, CancellationToken ct = default);

public sealed record PasswordSignInRequest
{
    public required string Identifier { get; init; }
    public required string Password { get; init; }
    public string? DeviceToken { get; init; }
    public string? UserAgent { get; init; }
    public string? IpAddress { get; init; }
}
```

That also solves where the user agent comes from: the endpoint reads it from `HttpContext` and puts
it here, so `Core` never learns what an HTTP request is.

PR labelled `breaking`; version bump stays minor per the pre-1.0 resolver.

---

## 10. Test plan

The brief's eight, plus what falls out of section 8:

- Device trust issued, then each of the eight D4 operations, then the token presented → **challenged,
  not skipped**, and the row gone. Eight tests, named for the operation.
- A device token presented as a bearer token to `/api/me` → 401.
- A rotated device token presented again → family revoked, siblings dead.
- A device-trusted sign-in: `amr` has `mfa`, has **no** `otp`, `toa_2fa_source` is `device`, and
  `toa_2fa_at` is the original challenge rather than now.
- Past the absolute lifetime, rejected despite use yesterday.
- Locked account refused despite a valid device token, and the lockout counter still incremented.
- Under `RequiredForAll`, an unenrolled user gains nothing from any device token.
- **8.1**: a device-trusted sign-in does not extend `FamilyStartedAt` and does not start a new family.
- A sign-out leaves device trust intact.
- `MaxDevicesPerUser` exceeded revokes the oldest family, not the newest.

---

## What changed while implementing this

Signed off as proposed. Four things the proposal did not have, and one bug the end-to-end run found
that no unit test would have.

### 1. The bug: `/auth/login` rotated the device token and did not return it

A device-trusted sign-in rotates the token. `/auth/login` returned `result.Tokens` and dropped
`result.TrustedDevice`, so the caller kept holding the token it had just spent. The next sign-in
presented an already-rotated token, which is the theft signal, so the family was revoked and the
device silently stopped working after exactly one use.

Invisible to every unit test, because the service layer was correct throughout - the gate rotated,
the store recorded it, `SignInResult.TrustedDevice` was populated. Only the HTTP shape lost it. The
same three-things-must-coincide pattern: it needs a device trust, a second sign-in, and someone
looking at the response body.

Both endpoints now share one `SignInSucceeded` helper.

### 2. `/auth/2fa/verify` and `/auth/login` disagreed about casing

Found while fixing the above. `/auth/login` returned `accessToken` from `TokenPair`;
`/auth/2fa/verify` returned `access_token` from a hand-written anonymous object added in Phase 4. A
client had to parse both.

I first unified on camelCase, for internal consistency with the rest of the package. That was the
weaker call and it was corrected before merge: **every sign-in response now uses the RFC 6749 names**
- `access_token`, `refresh_token`, `expires_in`, `token_type` - because a token endpoint is a place
where a standard already exists and anyone integrating expects it. Consistency with our own earlier
mistake is not worth preserving.

The line: **token responses are OAuth-shaped, everything else is camelCase.** `/auth/2fa` and
`/auth/devices` return this package's own shapes, which no standard names, so they stay camelCase.
Requests bind to our records and stay camelCase too - `deviceToken`, `rememberDevice`. Documented,
because the asymmetry is otherwise something a consumer discovers.

**This breaks `/auth/login`, `/auth/refresh` and `/auth/register` from 0.1.0, and
`/auth/2fa/verify` from 0.2.0.** Cheap now, and steadily less so.

### 3. `ToamaisutaaRefreshToken` gained two more columns

`TwoFactorSource` and `SecondFactorAt`, for exactly the reason `AuthenticationMethods` was added last
phase: without them, a refresh reports a device-trusted session as having no second-factor source at
all, and a step-up policy starts failing one access-token lifetime after a good sign-in. Caught by
writing the refresh path rather than by testing it.

Also: the first generated migration had `SecondFactorAt` as a native `timestamp with time zone`,
because the converter was applied on the new table but not on the refresh-token column. Regenerated
across all four providers after fixing the configuration.

### 4. D3 is the security guarantee, but not enough for the device list

`Revoked_when_two_factor_is_disabled` failed on the first run, and correctly. The stamp check is
lazy - it fires when a token is presented - so disabling two-factor left a row that could never be
honoured sitting in the user's device list looking live. Section 8.3 predicted the state and
prescribed "reject, delete, continue", which only runs when a challenge is required; disabling means
no challenge, so nothing ever looked.

Revocation is now **explicit** at every stamp-bumping site as well: `BumpSecurityStampAsync` in
`TwoFactorService` and both password paths in `PasswordAccountService`. The stamp check stays as the
backstop that nothing forgotten is ever actually honoured.

So the honest version of section 1's conclusion: **D3 covers five of eight for security. It covers
none of them for list accuracy.** Both mechanisms are needed, for different reasons.

### 5. `TwoFactorSignInRequest`

`VerifyTwoFactorAsync` needed remember-device, a label, a user agent and an address. Same reasoning
as `PasswordSignInRequest`, applied without asking because the principle was already signed off.

### Verification performed

- **191 tests green**, including the eight named D4 revocations, the loop that would defeat the
  absolute lifetime, sign-out *not* revoking, lockout ahead of device logic, and `RequiredForAll`.
- **All four migration assemblies regenerated together**, with every new instant column confirmed
  integer on all four providers.
- **End to end over HTTP**: a device-trusted sign-in returning `amr` `["pwd","mfa"]` with no `otp`,
  `toa_2fa_source=device`, and `toa_2fa_at` reporting the original live challenge rather than now;
  the device token refused as a bearer token with 401; a rotated token replayed revoking the family
  and its sibling; the device list with label, `::/48` truncated address and `isCurrent`; and after a
  password change, a challenge instead of a skip and an empty list.
- **The log line the brief asked for**: `Revoked 2 trusted device(s) for user ...: password-changed.`
- **No device token, enrolment secret or recovery code anywhere in the sample's log.**

## Open items

1. `toa_2fa_at` as well as `toa_2fa_source`, or just the source.
2. `IpAddressStorage` as a three-position enum, or the boolean flag the brief specifies.
3. `MaxDevicesPerUser` at all, and 10 as its default.
4. The `PasswordSignInRequest` record and its one break, or an optional parameter.
5. Section 1's conclusion: recovery-code redemption and refresh reuse revoke device trusts
   **explicitly** rather than by bumping the stamp, because bumping it in either place has a side
   effect that is wrong. Confirm you agree with the reasoning, not just the outcome.
