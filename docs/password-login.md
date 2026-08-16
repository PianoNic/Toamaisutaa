# Local password login

The fallback, for deployments that cannot run an identity provider. Switching it on means becoming
the identity provider - storing credentials, deciding who is who, issuing something the client
presents afterwards. Use OIDC if you can.

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);   // section "LocalLogin"
builder.Services.AddSingleton<IPasswordResetNotifier, YourEmailSender>();

app.MapToamaisutaaPasswordEndpoints();
```

Writing the browser side of this? [Using this from a SPA](/spa) covers the whole flow in one place -
the sign-in branch, refresh on 401, and where the tokens should live.

It needs `AddToamaisutaaBearer` as well - the tokens it issues are validated by the same pipeline
that validates your identity provider's, which is why `Toamaisutaa.AspNetCore` depends on
`Toamaisutaa.OpenIdConnect`. A store registration and an `IPasswordResetNotifier` are also required,
and all three are checked at startup rather than at the first request.

## The endpoints

| Method | Route | Answers |
|---|---|---|
| POST | `/auth/login` | 200 with a token pair, 200 with a two-factor challenge, or 401 |
| POST | `/auth/refresh` | 200 with a rotated pair, or 401 |
| POST | `/auth/logout` | 204 |
| POST | `/auth/register` | 201, 400, or 409. Only mapped when `AllowSelfRegistration` is true |
| POST | `/auth/password` | 204. Authenticated. Sets a first password or changes an existing one |
| POST | `/auth/password/forgot` | 204, always |
| POST | `/auth/password/reset` | 204 or 400 |
| POST | `/auth/users` | 201, 400, or 409. Authenticated. Only mapped when an `IAdminPasswordIssuedNotifier` is registered |
| POST | `/auth/users/{userId}/password` | 204 or 400. Authenticated. Only mapped when an `IAdminPasswordIssuedNotifier` is registered |
| POST | `/auth/invitations` | 201 or 400. Authenticated. Only mapped when an `IInvitationNotifier` is registered |
| POST | `/auth/invitations/complete` | 201 with a token pair, 400, or 409. Only mapped when an `IInvitationNotifier` is registered |

::: warning Requests are camelCase, token responses are not
Request bodies bind to this package's own records, so they are camelCase: `identifier`,
`refreshToken`, `newPassword`. **Sign-in responses use the RFC 6749 names** - `access_token`,
`refresh_token`, `expires_in`, `token_type` - because a token endpoint is a place where a standard
already exists.

The asymmetry is deliberate and it is the one thing here you cannot guess. Everything else this
package returns is camelCase.
:::

### Bodies

**`POST /auth/login`** - `deviceToken` is optional, and only meaningful with
[trusted devices](/trusted-devices).

```json
{ "identifier": "ada", "password": "correct horse battery staple", "deviceToken": null }
```

Answers **200** with a token pair. `recovery_codes_running_low` is `true` or `null`, never `false`;
`device_token` and `device_expires_in` are null unless a device was trusted.

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M",
  "expires_in": 900,
  "token_type": "Bearer",
  "recovery_codes_running_low": null,
  "device_token": null,
  "device_expires_in": null
}
```

Or **200 with a challenge and no tokens**, for a user who has enrolled in
[two-factor authentication](/two-factor). Branch on `two_factor_required`, which is absent from the
shape above:

```json
{ "two_factor_required": true, "challenge": "No1CXq9-...", "expires_in": 300 }
```

**`POST /auth/refresh`** answers the same token-pair shape, or 401.

```json
{ "refreshToken": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M" }
```

**`POST /auth/logout`** answers 204 whether or not that token existed.

```json
{ "refreshToken": "VWv8Paxg53FWF4HQ_Xzwp8o1EI3YWLSV4PbZAoH1x2M" }
```

**`POST /auth/register`** answers **201** with the same token-pair shape, so a registration signs the
user straight in.

```json
{ "userName": "ada", "email": "ada@example.com", "password": "correct horse battery staple" }
```

**`POST /auth/password`** - authenticated. Omit `currentPassword` when the account arrived through an
identity provider and is gaining its first password. Answers 204 or 400.

```json
{ "currentPassword": "the old one", "newPassword": "the new one" }
```

**`POST /auth/password/forgot`** answers 204 always - for an unknown address and for an account an
identity provider owns alike.

```json
{ "email": "ada@example.com" }
```

**`POST /auth/password/reset`** answers 204 or 400.

```json
{ "token": "the token from the notifier", "newPassword": "the new one" }
```

**`POST /auth/users`** - authenticated, provisions an account on someone else's behalf. `password` is
optional; omit it and Toamaisutaa generates one. Answers 201, 400, or 409. Never signs the caller in
as the new account, and the response never carries a password - see
[Admin-provisioned accounts](/provisioning-accounts#admin-provisioned-accounts).

```json
{ "userName": "newteacher", "email": "newteacher@example.com", "password": null }
```

```json
{ "userId": "0199...", "userName": "newteacher", "email": "newteacher@example.com" }
```

**`POST /auth/users/{userId}/password`** - authenticated, overwrites `userId`'s password
unconditionally. `password` is optional; omit it and Toamaisutaa generates one. Answers 204 or 400,
never a password.

```json
{ "password": null }
```

**`POST /auth/invitations`** - authenticated, reserves an account with nothing but an email. Answers
201 or 400. Never returns the invitation token - see
[Completing a reserved invitation](/provisioning-accounts#completing-a-reserved-invitation).

```json
{ "email": "newparent@example.com" }
```

```json
{ "userId": "0199...", "email": "newparent@example.com" }
```

**`POST /auth/invitations/complete`** - anonymous, but only usable with a valid token. Sets the user
name and password on the one reserved account the token names, and signs in - the same shape
`/auth/register` answers with. Answers 201, 400, or 409 for a taken user name.

```json
{ "token": "the token from the notifier", "userName": "newparent", "password": "the one they chose" }
```

### The two error shapes

**A credential that was not accepted** answers 401 with the RFC 6749 shape. Wrong password, no such
account, locked out and an unknown refresh token are all this one body, because telling them apart
tells a caller which user names are real:

```json
{ "error": "invalid_grant", "error_description": "The credentials are not valid." }
```

**Input the caller can correct** answers 400 - or 409 for a taken user name - with a camelCase array.
These strings are written to be shown to the person who typed the input:

```json
{ "errors": ["Use at least 8 characters."] }
```

A successful sign-in returns a short-lived access token and an opaque refresh token. The access
token is signed locally and validated by the same bearer pipeline, so policies, `ICurrentUser` and
provisioning cannot tell the two apart.

A user may have a password, external logins, or both. Adding a password to an account that arrived
through OIDC is supported and touches nothing on the external side.

Once a user enrols in [two-factor authentication](/two-factor), `/auth/login` returns a challenge
instead of tokens and the sign-in finishes at `/auth/2fa/verify`.

## Things to know before switching it on

Password hashing, and how to replace it, is its own page: [Password hashing](/password-hashing).
So are the other three swap-this-interface seams - the password rules, what goes in the access
token, and roles: [Customizing local password login](/customizing-password-login).

### Lockout is a denial-of-service vector, on purpose

Five failures in fifteen minutes locks an account for fifteen minutes, counted against the account
rather than the caller. Someone who knows a user name can keep that person locked out. The
alternative is an unthrottled online guessing oracle, which is worse. Per-IP rate limiting on the
anonymous endpoints covers the other half, and is enforced by the endpoints themselves rather than
by middleware you have to remember to add.

### Registration reveals whether an account exists

A taken user name answers 409. Hiding that needs an email round trip, and email delivery is
deliberately not in this package. Registration is off by default; turning it on accepts this.

That email round trip - and two other ways to get someone into an account without open
registration - are their own page: [Provisioning accounts](/provisioning-accounts).

### Revoking sessions means local sessions

A password change or reset revokes every refresh token this package issued. An access token your
identity provider issued keeps working until it expires, because we cannot revoke it.

### Expired tokens accumulate unless you sweep them

`AddToamaisutaaTokenCleanup()` runs a periodic delete. Without it, plan to call
`IRefreshTokenStore.DeleteExpiredAsync` from your own scheduler.

## Refresh tokens

Stored hashed, never in the clear, and rotated on every use. Presenting a token that has already
been rotated proves two parties hold the chain, so the whole family is revoked and the event is
logged loudly - the standard mitigation for a stolen refresh token.

Rotation alone would keep a session alive forever, so a chain also has an absolute lifetime
(`RefreshTokenAbsoluteLifetime`, 90 days) measured from the sign-in that started it.

### A new claim and the refresh path

If you replace `IAccessTokenIssuer` and add a claim, decide in the same change what
`RefreshAsync` does with it: **recompute it, carry it on the refresh token row, or drop it
deliberately.** All three are defensible; not having decided is not.

A refresh that silently drops a claim produces a token that is correct at sign-in and wrong exactly
one `AccessTokenLifetime` later, which reads as a policy failure rather than a refresh failure. This
package has made that mistake three times and never once caught it with a test.

## Calling the services yourself

The endpoints are a convenience, not the API. `IPasswordSignInService` and `IPasswordAccountService`
are public, so an application that routes everything through its own handlers - a mediator, a
different transport, a background job - can skip `MapToamaisutaaPasswordEndpoints` entirely and call
them directly.

```csharp
public sealed class SignInHandler(IPasswordSignInService signIn)
{
    public async Task<YourResult> Handle(YourCommand command, CancellationToken cancellationToken)
    {
        var result = await signIn.SignInAsync(
            new PasswordSignInRequest
            {
                Identifier = command.Identifier,
                Password = command.Password,
                UserAgent = command.UserAgent,     // yours to supply - Core never sees an HTTP request
                IpAddress = command.IpAddress,
            },
            cancellationToken);

        return result.Outcome switch
        {
            SignInOutcome.Succeeded => YourResult.SignedIn(result.Tokens!),
            SignInOutcome.TwoFactorRequired => YourResult.NeedsCode(result.Challenge!),
            _ => YourResult.Refused(),
        };
    }
}
```

Two things worth knowing before you build on them:

- **`SignInOutcome` tells you what really happened, and the endpoints deliberately throw that away.**
  `UnknownUser`, `InvalidPassword` and `LockedOut` are three different values here and one 401 on the
  wire, because telling a caller which one it was tells them which user names are real. If you shape
  your own response, keep that collapse.
- **Every result type is a sealed record with public `init` members**, so they compose into DTOs of
  your own and construct in a test without reflection. `SignInResult.Succeeded` is computed from
  `Outcome`, so set the outcome rather than looking for a setter.

The implementations behind these interfaces are `internal`. Inject the interface - which is what DI
hands you - rather than expecting to construct one.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `LocalLogin:SigningKey` | | Base64, at least 32 bytes. Required. No generated fallback |
| `LocalLogin:Issuer` | `toamaisutaa` | Changing it invalidates every token in flight |
| `LocalLogin:Audience` | `Oidc:ClientId` | |
| `LocalLogin:AccessTokenLifetime` | `00:15:00` | |
| `LocalLogin:RefreshTokenLifetime` | `14.00:00:00` | |
| `LocalLogin:RefreshTokenAbsoluteLifetime` | `90.00:00:00` | How long a rotating chain may live |
| `LocalLogin:Pbkdf2Iterations` | `600000` | Startup floor |
| `LocalLogin:SaltSizeBytes` / `HashSizeBytes` | `16` / `32` | Startup floor |
| `LocalLogin:Pepper` / `PepperVersion` / `RetiredPeppers` | none / `1` / empty | See [password hashing](/password-hashing#a-pepper-is-available-and-off-by-default) |
| `LocalLogin:LockoutEnabled` | `true` | |
| `LocalLogin:MaxFailedAttempts` | `5` | |
| `LocalLogin:LockoutWindow` / `LockoutDuration` | `00:15:00` | |
| `LocalLogin:MinimumPasswordLength` | `8` | NIST: a length floor, no composition rules |
| `LocalLogin:MaximumPasswordLength` | `128` | Not a strength rule - a bound on an anonymous endpoint |
| `LocalLogin:PasswordResetTokenLifetime` | `01:00:00` | Single use |
| `LocalLogin:InvitationTokenLifetime` | `7.00:00:00` | Single use |
| `LocalLogin:AllowSelfRegistration` | `false` | When false the endpoint is not mapped at all |
| `LocalLogin:EndpointPrefix` | `/auth` | |
| `LocalLogin:RateLimit:Enabled` | `true` | Per caller address, fixed window |
| `LocalLogin:RateLimit:PermitLimit` / `Window` | `10` / `00:01:00` | |
| `LocalLogin:TokenCleanupInterval` | `06:00:00` | Only used by `AddToamaisutaaTokenCleanup()` |
