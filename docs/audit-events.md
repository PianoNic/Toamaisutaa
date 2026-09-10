# Audit events

Every security-relevant outcome is published to any sink you register, so an audit table is a class
you write rather than a log scraper you maintain.

```csharp
builder.Services.AddToamaisutaaAuthenticationEventSink<AuditSink>();
```

Nothing else needs switching on. With no sink registered nothing is published and the sign-in path
behaves exactly as it did before, which is the default.

## A sink

```csharp
internal sealed class AuditSink(AppDbContext db) : IAuthenticationEventSink
{
    public async Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
    {
        db.AuditEntries.Add(new AuditEntry
        {
            Kind = authenticationEvent.Kind,
            UserId = authenticationEvent.UserId,
            OccurredAt = authenticationEvent.OccurredAt,
            Methods = string.Join(' ', authenticationEvent.AuthenticationMethods),
            Detail = authenticationEvent switch
            {
                SignInFailed failed => failed.Reason.ToString(),
                SessionRevoked revoked => revoked.Reason,
                TrustedDeviceRevoked revoked => revoked.Reason,
                _ => null,
            },
        });

        await db.SaveChangesAsync(cancellationToken);
    }
}
```

Sinks are registered scoped, so a sink can take the same unit of work the request is already using,
and built on the first event of that request rather than on every request that happens to touch an
authentication service. Register as many as you like: all of them are called, in registration order.

## What is published

Every event carries `Kind`, `OccurredAt`, `UserId` and the `amr` values the resulting token carries.
`Kind` is a stable string meant for a column - it never changes once shipped, which a type name
cannot promise.

| Kind | Published when | Also carries |
|---|---|---|
| `sign-in-succeeded` | A token pair was issued | `SessionId`, `TwoFactorSource` |
| `sign-in-failed` | A sign-in issued nothing | `Reason` |
| `account-locked-out` | The failed attempt that crossed the threshold | `LockedOutUntil` |
| `password-changed` | A password was set with proof of the old one, or by an administrator | `SetByAdministrator` |
| `password-reset` | A password was set by spending a reset token | |
| `email-changed` | A verification link was redeemed, so the address is now the one it named | `PreviousEmail`, `Email` |
| `two-factor-enrolled` | An enrolment was confirmed with a working code | |
| `two-factor-disabled` | A confirmed second factor was turned off | |
| `two-factor-failed` | A second factor was presented and refused | `Reason` |
| `recovery-code-used` | A recovery code was spent | `RunningLow` |
| `passkey-registered` | A WebAuthn credential was added to an account | `PasskeyId`, `Label` |
| `passkey-removed` | One was deleted | `PasskeyId` |
| `trusted-device-added` | A device was remembered | `DeviceId`, `Label` |
| `trusted-device-revoked` | A device stopped being trusted | `DeviceId`, `Reason` |
| `session-revoked` | A refresh family stopped being usable | `SessionId`, `Reason` |
| `refresh-token-reuse-detected` | An already-rotated refresh token was presented | `SessionId` |

`SessionId` is the refresh family, which is also what the access token carries as `toa_sid`, so a
`sign-in-succeeded` row and the `session-revoked` row that ends it line up on one value.

`email-changed` carries both addresses because the old one is the half that cannot be read off the
account afterwards, and it is the one change that moves where every later reset link and magic link
is sent. `PreviousEmail` equal to `Email` is the first verification of the address already on file.

A `Reason` on a revocation is the same string written to the revoked row - `signed-out`,
`password-changed`, `security-stamp-changed`, `refresh-token-reuse`, `device-limit-reached`,
`revoked-by-user` and the rest. `DeviceId` or `SessionId` being null means every one of them went at
once, which is what a credential change does.

::: tip The sink is told more than the caller is
`/auth/login` collapses every failure into one 401 precisely so a caller cannot tell an unknown
account from a wrong password. `SignInFailed.Reason` is the internal outcome - `UnknownUser`,
`InvalidPassword`, `LockedOut` - because a sink is on the inside of that distinction.
:::

## What is deliberately not an event

- **A refresh.** Rotation proved nothing; it renewed something already proved. Counting one as a
  sign-in reports a sign-in every access-token lifetime for anyone who left a tab open.
- **Beginning a two-factor enrolment.** Until it is confirmed, nothing about the account changed.
- **Reading anything.** These are outcomes, not requests.

## Three rules this keeps

**No event carries a secret.** Not a password, a TOTP secret, a recovery code, a reset or invitation
token, or a refresh token. The user id, the `amr` values and the time are enough to reconstruct what
happened, and an audit table usually outlives every key rotation anyone remembers to perform.

**A sink that throws never fails the request.** The exception is logged and the next sink still gets
the event. Auditing that turns a correct sign-in into a 500 is worse than no auditing. That covers a
sink whose own HTTP call or database command times out - those arrive as `TaskCanceledException`
without anything having cancelled the request, and only the request's own cancellation is let
through - and a sink that throws from its constructor, which is why sinks are built when the first
event of a request is published rather than when the services around them are resolved.

**Delivery is in-process and best effort.** There is no retry and no queue. A sink that must not
lose an event should write it somewhere durable itself - a row in the same transaction, an outbox -
rather than treat this call as a delivery guarantee.
