# Sessions

Where somebody is signed in, and how they end one they do not recognise.

```csharp
app.MapToamaisutaaSessionEndpoints();
```

Nothing else to register: sessions come with [local password login](/password-login), because they
are the refresh families it already issues.

## A session is a refresh family

One sign-in starts one family. Every refresh rotates the token inside it and the family stays the
same, which is why the session id on the access token - `toa_sid` - is stable for as long as the
person stays signed in.

So one entry in this list is one sign-in, not one access token, and revoking an entry ends the whole
chain rather than the fifteen minutes currently in flight.

## The endpoints

| Method | Route | Answers |
|---|---|---|
| GET | `/auth/sessions` | 200 with an array |
| DELETE | `/auth/sessions/{id}` | 204, or 404 |
| DELETE | `/auth/sessions` | 204. Signs out everywhere **else** |

All three are authenticated. The `GET` returns camelCase, because this is one of the package's own
shapes rather than a token response:

```json
[
  {
    "id": "019ff5ca-b7e9-7394-a875-c8ad616b14db",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0) ...",
    "ipAddress": "203.0.113.0/24",
    "createdAt": "2026-09-10T11:45:31.113+00:00",
    "lastUsedAt": "2026-09-10T14:02:07.900+00:00",
    "expiresAt": "2026-12-09T11:45:31.113+00:00",
    "authenticationMethods": ["pwd", "otp", "mfa"],
    "isCurrent": true
  }
]
```

`id` is the family id, which survives rotation - pass it back to `DELETE /auth/sessions/{id}`.

`isCurrent` marks the session the request itself was made on, read from the caller's own `toa_sid`.
No header to send: unlike the [device list](/trusted-devices#the-device-list), the caller's session
is already named on the bearer token they are holding.

`authenticationMethods` is what that session's tokens carry in `amr`, so a list can say which
sessions proved a second factor and which only ever proved a password.

`expiresAt` is the sooner of the live token's own expiry and the family's absolute lifetime.
Refreshing moves the first; nothing moves the second, so a session used every day still shows a date
that comes closer.

Sessions already past that point are not listed, although their rows stay until the next refresh
refuses them.

## Sign out everywhere else

`DELETE /auth/sessions` keeps the calling session and ends every other one. That asymmetry is the
point: a user who clicks this after seeing a session they do not recognise wants the other one gone,
not to be returned to the login form themselves.

To end their own as well, follow it with `POST /auth/logout`, or revoke it by id like any other.

A caller whose token has no `toa_sid` - one an identity provider issued - has no session of their own
to keep, so every one of them is revoked. The list still works for them, and marks none of them
current.

## What a revoke actually ends

The refresh family, immediately. The next `POST /auth/refresh` on that chain answers 401.

**Access tokens already issued keep working until they expire**, which is at most
`AccessTokenLifetime` - fifteen minutes by default. Nothing in this package can recall a signed JWT;
that is the trade a stateless token makes. This holds for every revocation - a sign-out, a password
change, a two-factor change - not only this one. Shorten `AccessTokenLifetime` if that window
matters, and read [security stamps](/password-login#revoking-sessions-means-local-sessions) for the
case where you want every session gone at once.

Every revoke publishes a `session-revoked` [audit event](/audit-events) with the reason
`revoked-by-user`, one per family, so a session somebody ended themselves appears in the same table
as the ones a password change ended for them.

**Trusted devices are deliberately left alone.** Ending a session is not a security event, and a
[trusted device](/trusted-devices) surviving it is the point of having trusted it. Revoke the device
too if that is what you meant.

## What is stored

Whatever the request that started the session carried, and only that:

- **`userAgent`** - the raw header, truncated to 256 characters, deliberately **not** parsed into
  "Firefox on Windows". That is either a dependency or a lookup table that rots.
- **`ipAddress`** - off by default. See below.

Both are recorded when the family starts and **carried across every rotation**. A refresh does not
take them again: `/auth/refresh` is the one call a background timer makes, so recomputing would
eventually describe every session as whatever last renewed it.

A session started before these columns existed shows no user agent, no address, and a `lastUsedAt` of
the Unix epoch until its next refresh.

### Addresses are off by default

`LocalLogin:IpAddressStorage` here, and `TrustedDevices:IpAddressStorage` for
[trusted devices](/trusted-devices), take the same values and are set independently:

| `IpAddressStorage` | Stores |
|---|---|
| `None` | Nothing. The default |
| `Truncated` | IPv4 to /24, IPv6 to /48 - "a different network", not "a person" |
| `Full` | The address |

::: warning
Anything other than `None` puts personal data in your database. Under GDPR that belongs in your
privacy notice, and the feature works without it. `Truncated` is the useful middle: it answers "is
this somewhere new" without identifying anyone.
:::

Behind a reverse proxy, the address the package sees is the proxy's unless
`UseForwardedHeaders` is configured - and configured with `KnownProxies`, or the header is whatever a
caller decided to send.

## Building the list into your own UI

`ISessionService` is public, so the three endpoints are optional:

```csharp
public sealed class SessionListHandler(ISessionService sessions, ICurrentUser currentUser)
{
    public async Task<IReadOnlyList<SessionSummary>> Handle(Guid? currentSessionId, CancellationToken cancellationToken)
    {
        var user = await currentUser.GetOrProvisionAsync(cancellationToken);
        return await sessions.ListAsync(user.Id, currentSessionId, cancellationToken);
    }
}
```

The current session id is passed in rather than read, because `Core` never learns what an HTTP
request is. Read it from `toa_sid` on the caller's token, the way the endpoint does.

`RevokeAsync` returns `false` for a session that does not exist **and** for one belonging to somebody
else. Keep those the same answer in whatever you return, or the endpoint becomes a way to discover
another account's session ids.

A custom `IRefreshTokenStore` has to implement `ListActiveAsync`: the live row of every family a user
has, not rotated and not revoked.

## Configuration

| Key | Default |
|---|---|
| `LocalLogin:SessionEndpointPrefix` | `/sessions`, appended to `LocalLogin:EndpointPrefix` |
| `LocalLogin:IpAddressStorage` | `None` |

`SessionEndpointPrefix` is a suffix, not a full path - the same way the two-factor endpoints append
`/2fa`. The default is `/auth/sessions`, and moving `LocalLogin:EndpointPrefix` moves these with it.
