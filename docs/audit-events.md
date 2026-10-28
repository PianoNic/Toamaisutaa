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

Every event carries `Kind`, `OccurredAt`, `UserId` and the `amr` values the resulting token carries,
and `ActorSubject`: the `sub` of whoever was signed in on the request that caused it. On an
administrator's action it names the administrator while `UserId` names the account acted on; on an
anonymous request, a sign-in for example, it is null.
`Kind` is a stable string meant for a column - it never changes once shipped, which a type name
cannot promise.

| Kind | Published when | Also carries |
|---|---|---|
| `sign-in-succeeded` | A token pair was issued | `SessionId`, `TwoFactorSource` |
| `sign-in-failed` | A sign-in issued nothing | `Reason` |
| `account-locked-out` | The failed attempt that crossed the threshold | `LockedOutUntil`, `SourceOnly`, `Strikes` |
| `password-changed` | A password was set with proof of the old one, or by an administrator | `SetByAdministrator` |
| `password-reset` | A password was set by spending a reset token | |
| `email-address-released` | An account lost an address it held unverified, because another proved the mailbox | `Email`, `ClaimedByUserId` |
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
| `account-created` | An account came into existence | `Source`: `registration`, `administrator`, `invitation` or `external-login` |
| `invitation-sent` | An invitation link was issued | `Email` |
| `password-reset-requested` | A reset link was issued (an unknown or unverified address issues nothing, and publishes nothing) | |
| `magic-link-requested` | A sign-in link was issued | |
| `email-change-requested` | A verification link for a new address was issued | `Email` |
| `external-login-authenticated` | A provider vouched for the account; the `sign-in-succeeded` with `fed` follows the exchange | `ProviderKey` |
| `external-login-linked` | A provider was linked, by the owner or by a verified address | `ProviderKey` |
| `external-login-unlinked` | The owner removed a linked provider | `ProviderKey` |
| `account-disabled` | An administrator disabled the account | |
| `account-enabled` | An administrator enabled it again | |

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

## Telling the owner

Nothing here mails anyone about their own account on its own. A sink is where to do it, since it
sees every change with the account's address to hand. The common ones: a password changed or reset,
an address changed - `EmailChanged.PreviousEmail` is the address to warn, since the new one is in the
hands of whoever just proved it - a passkey added, and a repeated lock:

```csharp
internal sealed class SecurityNotices(IUserStore users, YourMailer mailer) : IAuthenticationEventSink
{
    public async Task HandleAsync(AuthenticationEvent e, CancellationToken cancellationToken = default)
    {
        var to = e switch
        {
            EmailChanged { PreviousEmail: { } previous } changed when previous != changed.Email => previous,
            PasswordChanged or PasswordReset or PasskeyRegistered or AccountLockedOut { Strikes: > 1 }
                => e.UserId is { } id ? (await users.FindByIdAsync(id, cancellationToken))?.Email : null,
            _ => null,
        };

        if (to is not null)
            await mailer.SendSecurityNoticeAsync(to, e.Kind, e.OccurredAt, cancellationToken);
    }
}
```

## Mail that must not be lost

The package's own notifiers send from an in-memory queue of a thousand, behind the per-address rate
limit and a per-address cooldown. Enough callers spread across enough addresses can still fill it,
and a full queue drops new mail; a restart loses what is queued. If a reset or an invitation must
survive either, register notifiers that write to a durable outbox in your own database and send from
there.

## What is deliberately not an event

- **A refresh.** Rotation proved nothing; it renewed something already proved. Counting one as a
  sign-in reports a sign-in every access-token lifetime for anyone who left a tab open.
- **Beginning a two-factor enrolment.** Until it is confirmed, nothing about the account changed.
- **Reading anything.** These are outcomes, not requests.

## Three rules this keeps

**No event carries a secret.** Not a password, a TOTP secret, a recovery code, a reset or invitation
token, or a refresh token. The user id, the `amr` values and the time are enough to reconstruct what
happened.

**A sink that throws never fails the request.** The exception is logged and the next sink still gets
the event. That includes a sink that throws from its constructor, and one whose own call times out
with a `TaskCanceledException`; only the request's own cancellation is let through.

**Delivery is in-process and best effort.** There is no retry and no queue. A sink that must not
lose an event should write it somewhere durable itself - a row in the same transaction, an outbox -
rather than treat this call as a delivery guarantee.
