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

::: tip Request fields are camelCase, token responses are not
Requests bind to this package's own records, so they are camelCase: `deviceToken`, `rememberDevice`.
Sign-in *responses* use the RFC 6749 names - `access_token`, `refresh_token`, `expires_in`,
`token_type`, and alongside them `device_token` and `device_expires_in` - so a client that already
speaks OAuth token endpoints needs no mapping.
:::

## Storing it is the whole security of this feature

The package returns the token in a response body and reads it from a request body. It does not set
cookies, because your application owns its transport.

**An `HttpOnly; Secure; SameSite=Strict` cookie set by your application is the safe choice.** It
cannot be read by JavaScript, so a cross-site scripting bug cannot exfiltrate it.

**Putting it in `localStorage` means any XSS gets a permanent second-factor bypass.** Not a session,
not a stolen access token that expires in fifteen minutes - a token that skips 2FA for thirty days,
readable by any script that runs on your origin. That is the consequence; the choice is yours.

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

Backing all of that up: the user's security stamp is recorded on the device when it is trusted, and
compared every time it is used. A device established before any credential change is refused even if
something forgot to revoke it.

**Signing out does not revoke a device.** Signing out is not a security event, and a device surviving
it is the point of having trusted it.

## What it claims

A cached second factor is not a one-time password, and the token says so:

| Sign-in | `amr` | `toa_2fa_source` | `toa_2fa_at` |
|---|---|---|---|
| Password + TOTP | `["pwd","otp","mfa"]` | `otp` | now |
| Password + recovery code | `["pwd","mfa"]` | `recovery` | now |
| Password + trusted device | `["pwd","mfa"]` | `device` | **the original live challenge** |

`mfa` still holds - a second factor was performed, just not now - so a `Toamaisutaa.TwoFactor` policy
keeps working. What changes is `toa_2fa_at`, which reports when the factor was actually presented.

### Step-up is something you can express, not something this package does

**Toamaisutaa ships the claims, not the enforcement.** There is no step-up API here: nothing will
interrupt a request to ask for a fresh code, and nothing re-challenges a user mid-session. What the
token gives you is enough information to write the policy yourself, out of parts you already have:

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

A request failing that gets a 403. Sending the user back through a live challenge, and getting them
where they were going afterwards, is your application's flow to build - this package has no view on
what that should look like.

`toa_2fa_at` exists because without it "fresh" could only mean "not cached", which would wrongly
accept a live code entered twenty minutes ago.

## Lifetime is absolute

Thirty days by default, measured from when the device was **first** trusted. Rotation does not extend
it. A device signed in from every single day still has to complete a live challenge after thirty
days, which is the difference between an expiry and a suggestion.

`MaxDevicesPerUser` caps the list at ten; above it, the oldest is revoked. Every live device is a
second factor somebody is not being asked for, and without a cap they accumulate one per browser.

## The device list

```
GET    /auth/devices
DELETE /auth/devices/{id}
DELETE /auth/devices
```

Send the caller's own device token in an `X-Toamaisutaa-Device` header on the `GET` and the matching
entry comes back with `isCurrent: true`, so a UI need not invite somebody to revoke the device they
are sitting at.

## What is stored, and what is not

`Label` is whatever your application passes - the package does not invent one. `UserAgent` is the raw
string, truncated, and deliberately **not** parsed into "Firefox on Windows": that is either a
dependency or a lookup table that rots.

Addresses are off by default:

| `TrustedDevices:IpAddressStorage` | Stores |
|---|---|
| `None` | Nothing. The default |
| `Truncated` | IPv4 to /24, IPv6 to /48 - "a different network", not "a person" |
| `Full` | The address |

::: warning
Anything other than `None` puts personal data in your database. Under GDPR that belongs in your
privacy notice, and it is not needed for the feature to work. `Truncated` is the useful middle: it
answers "is this somewhere new" without identifying anyone.
:::

## Never log the device token

It is a credential worth thirty days of skipped second factors. Nothing in this package logs it, and
nothing in yours should either - the same rule as the [enrolment secret](/two-factor). Log the
device's family id, which is what the list and revoke endpoints use anyway.

## Configuration

| Key | Default |
|---|---|
| `Lifetime` | `30.00:00:00` |
| `MaxDevicesPerUser` | `10`, `0` for unlimited |
| `IpAddressStorage` | `None` |
| `EndpointPrefix` | `/auth/devices` |
