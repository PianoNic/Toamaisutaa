# Trusted devices

"Remember this device": a user who completes a live two-factor challenge can skip the second factor
on that device until the trust expires.

```csharp
builder.Services.AddToamaisutaaTrustedDevices(builder.Configuration);   // section "TrustedDevices"

app.MapToamaisutaaTrustedDeviceEndpoints();
```

Needs [two-factor authentication](/two-factor) and local password login, both checked at startup.

## The one thing to hold on to

**A trusted device is a cached second factor and nothing more.** It never stands in for the password,
and it never survives anything that would have invalidated the second factor. Everything below
follows from that.

## How it flows

1. `/auth/login` with a password → a challenge, as usual.
2. `/auth/2fa/verify` with `"rememberDevice": true` → tokens **and** a `device_token`.
3. `/auth/login` with `identifier`, `password` and `"deviceToken": "…"` → tokens, no challenge.

The device token rotates on every use, so the response to step 3 contains a **new** `device_token`.
Store it and discard the old one - presenting a spent token is the theft signal, and it revokes the
device.

Request fields are camelCase (`deviceToken`, `rememberDevice`) and the response fields snake_case
(`device_token`, `device_expires_in`), like [every sign-in body](/password-login#bodies).

## Storing it is the whole security of this feature

The package returns the token in a response body and reads it from a request body; it does not set
cookies. **An `HttpOnly; Secure; SameSite=Strict` cookie set by your application is the safe
choice**, because JavaScript cannot read it. **In `localStorage`, any XSS gets a token that skips 2FA
for thirty days.** See [where to put the tokens](/spa#where-to-put-the-tokens).

## What revokes it

Every one of these kills every trusted device for that user:

| | |
|---|---|
| Password changed | Also moves the security stamp |
| Password reset | Also moves the security stamp |
| Two-factor enrolled, disabled, or recovery codes regenerated | Also moves the security stamp |
| **A recovery code redeemed** | A recovery code means the authenticator is gone. Trusting devices at that moment is exactly backwards |
| **Refresh-token reuse detected** | Already a theft signal |
| The user revoking one, or all | `DELETE /auth/devices/{id}` or `DELETE /auth/devices` |

Backing that up, the user's security stamp is recorded on the device when it is trusted and compared
every time it is used, so a device established before any credential change is refused regardless.

**Signing out does not revoke a device.** Signing out is not a security event, and a device surviving
it is the point of having trusted it.

## What it claims

A cached second factor is not a one-time password, and the token says so:

| Sign-in | `amr` | `toa_2fa_source` | `toa_2fa_at` |
|---|---|---|---|
| Password + TOTP | `["pwd","otp","mfa"]` | `otp` | now |
| Password + recovery code | `["pwd","mfa"]` | `recovery` | now |
| Password + trusted device | `["pwd","mfa"]` | `device` | **the original live challenge** |
| …then a [step-up](/two-factor#step-up) | `["pwd","mfa","otp"]` | `otp` | now |

`mfa` still holds - a second factor was performed, just not now - so a `Toamaisutaa.TwoFactor` policy
keeps working. What changes is `toa_2fa_at`, which reports when the factor was actually presented.

### Every claim a locally issued token carries

| Claim | Standard | Means |
|---|---|---|
| `sub`, `preferred_username`, `email`, `name` | yes | The usual profile claims |
| `amr` | RFC 8176 | Every method this session has used. Only ever grows |
| `toa_stamp` | no | The user's security stamp when the session was minted |
| `toa_sid` | no | The refresh family - the [session](/sessions). Stable across every rotation |
| `toa_2fa_source` | no | The most recent second factor: `otp`, `recovery`, `device` or `passkey` |
| `toa_2fa_at` | no | Unix seconds of the last **live** second factor |
| `toa_2fa_required` | no | Set when enforcement demands an enrolment this user has not made |

`toa_sid` is an identifier, not a credential: nothing authorises on it. It is namespaced rather than
the registered `sid` so it cannot collide with an identity provider's own `sid`.

### Requiring a fresh factor

`toa_2fa_at` is what makes freshness expressible: without it "fresh" could only mean "not cached",
which would wrongly accept a live code entered twenty minutes ago.

```csharp
options.AddPolicy("FreshSecondFactor", policy => policy
    .RequireAuthenticatedUser()
    .RequireFreshSecondFactor(TimeSpan.FromMinutes(5)));
```

That is the same check written by hand, if you would rather see the mechanism:

```csharp
options.AddPolicy("FreshSecondFactor", policy => policy
    .RequireAuthenticatedUser()
    .RequireAssertion(context =>
    {
        var at = context.User.FindFirst("toa_2fa_at")?.Value;
        return long.TryParse(at, out var seconds)
            && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - seconds < 300;
    }));
```

Both fail closed: a token with no `toa_2fa_at`, or one that cannot be parsed, is refused rather than
waved through.

A request failing the policy gets a **403**. What the user does next is
[step-up](/two-factor#step-up), which asks for one code and returns a new access token for the same
session - no sign-out, no new refresh token.

## Lifetime is absolute

Thirty days by default, measured from when the device was **first** trusted. Rotation does not extend
it: a device signed in from every single day still has to complete a live challenge after thirty
days.

`MaxDevicesPerUser` caps the list at ten; above it, the oldest is revoked.

## The device list

```
GET    /auth/devices
DELETE /auth/devices/{id}
DELETE /auth/devices
```

Send the caller's own device token in an `X-Toamaisutaa-Device` header on the `GET` and the matching
entry comes back with `isCurrent: true`, so a UI need not invite somebody to revoke the device they
are sitting at.

All three are authenticated. The `GET` returns an array - camelCase, because this is one of this
package's own shapes rather than a token response:

```json
[
  {
    "id": "019ff5ca-b7e9-7394-a875-c8ad616b14db",
    "label": "Ada's laptop",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0) ...",
    "ipAddress": "::/48",
    "createdAt": "2026-08-12T11:45:31.113+00:00",
    "lastUsedAt": "2026-08-12T11:45:31.113+00:00",
    "expiresAt": "2026-09-11T11:45:31.113+00:00",
    "isCurrent": true
  }
]
```

`id` is the family id, which survives rotation - pass it back to `DELETE /auth/devices/{id}`. Both
deletes answer 204 with no body, and revoking an id that does not exist or belongs to someone else
answers 404, because those are the same answer to whoever asked.

### Where the device token appears

Nowhere of its own: it rides on the ordinary sign-in body, alongside the tokens.

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 900,
  "token_type": "Bearer",
  "recovery_codes_running_low": null,
  "device_token": "JvYFOmcNekB5SvHZWfcdMc-MdqEXFFZB8rmQtbDh5jY",
  "device_expires_in": 2592000
}
```

`device_expires_in` counts down from when the family was established rather than restarting, so a
rotated token reports a smaller number each time. That is the absolute lifetime being visible rather
than a bug.

### Building the list into your own UI

`ITrustedDeviceService` is public, so the three endpoints above are optional. Inject it and shape
the response yourself:

```csharp
public sealed class DeviceListHandler(ITrustedDeviceService devices, ICurrentUser currentUser)
{
    public async Task<IReadOnlyList<TrustedDeviceSummary>> Handle(CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        return await devices.ListAsync(user.Id, cancellationToken);
    }
}
```

`RevokeAsync` returns `false` for a device that does not exist **and** for one belonging to somebody
else. Keep those the same answer in whatever you return, or the endpoint becomes a way to discover
another account's device ids.

`isCurrent` is the one thing you lose going this route: the endpoint sets it by reading the
`X-Toamaisutaa-Device` header, and a handler of your own has no header to read unless you pass the
token through yourself.

## What is stored, and what is not

`Label` is whatever your application passes - the package does not invent one. `UserAgent` is the raw
string, truncated, and deliberately **not** parsed into "Firefox on Windows": that is either a
dependency or a lookup table that rots.

Addresses are off by default. `TrustedDevices:IpAddressStorage` takes `None`, `Truncated` or `Full`,
exactly as [for sessions](/sessions#addresses-are-off-by-default) - read the GDPR note there before
turning it on.

## Never log the device token

It is a credential worth thirty days of skipped second factors. Nothing in this package logs it, and
nothing in yours should either. Log the device's family id, which is what the list and revoke
endpoints use anyway.

## Configuration

| Key | Default |
|---|---|
| `Lifetime` | `30.00:00:00` |
| `MaxDevicesPerUser` | `10`, `0` for unlimited |
| `IpAddressStorage` | `None` |
| `EndpointPrefix` | `/devices`, appended to `LocalLogin:EndpointPrefix` |

`EndpointPrefix` is a suffix, not a full path - the same way the two-factor endpoints append `/2fa`.
The default is still `/auth/devices`, and moving `LocalLogin:EndpointPrefix` moves these with it.
