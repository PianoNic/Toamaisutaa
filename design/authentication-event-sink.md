# Authentication event sink

Issue #67. One interface in `Abstractions`, a record hierarchy of events, and every security-relevant
outcome published to whatever a consumer registers.

## The shape

- `IAuthenticationEventSink.HandleAsync(AuthenticationEvent, CancellationToken)` - one method, and
  the only public interface added.
- `AuthenticationEvent` is abstract with `Kind`, `OccurredAt`, `UserId` and `AuthenticationMethods`;
  thirteen sealed records derive from it.
- `AuthenticationEventPublisher` in `Core` is `internal` and concrete. It takes
  `IEnumerable<IAuthenticationEventSink>`, so with none registered every call site is a loop over
  nothing rather than a null check.

## Decisions worth the record

**No `NullAuthenticationEventSink`.** The issue asked for "a default implementation that is a
no-op". Zero registered sinks already is that no-op, and shipping a null object would be a public
type whose only purpose is to be registered instead of nothing. The publisher is what makes the
call sites unconditional.

**`Kind` is a stable string, not the type name.** A sink writing rows needs a discriminator that
outlives a rename, and a column value is forever in a way a type name is not.

**Events are published in-request, best effort, with no retry.** A queue or an outbox is a decision
about the consumer's infrastructure, and this package has no business making it. What it does
guarantee is that a sink cannot fail the request: exceptions are caught and logged, `catch (Exception
ex) when (ex is not OperationCanceledException)`, matching what `RequestPasswordResetAsync` already
does with a notifier. A cancelled request is already over, so cancellation is not swallowed. (That
filter was wrong for the reason recorded under "What changed afterwards" below.)

**A refresh publishes no `SignInSucceeded`.** `IssueAsync` is shared by sign-in and rotation, so it
takes an explicit `newSignIn` rather than inferring it from `familyId is null`. Counting rotations
as sign-ins would report one per access-token lifetime for anyone with a tab open, which is the
number an audit table is least able to recover from.

**Every revocation publishes, from one place per service.** `RevokeFamilyAsync` on the sign-in
service, `RevokeAllSessionsAsync` on the account service and `RevokeFamilyAsync` on the device gate
each wrap the store call and the publish together, so the reason string written to the row and the
reason handed to a sink cannot drift apart. `SessionId` or `DeviceId` being null is how "all of
them" is expressed, rather than one event per row for something that was one decision.

**Reuse detection publishes twice.** `RefreshTokenReuseDetected` and then the `SessionRevoked` and
`TrustedDeviceRevoked` it causes. "A theft was detected" and "these things were taken away" are
different facts, and an audit trail wants both.

**`ChallengeRedemption.UserId` became `Guid?`.** A failed redemption used to name nobody, which was
fine when nothing read it. `TwoFactorFailed` should name the account whenever it can, and the only
failure that genuinely cannot is a challenge token that matches no row.

## What is not published, and why

- Beginning a two-factor enrolment. Nothing about the account has changed until it is confirmed.
- Registration and admin account creation. They are provisioning, not an authentication outcome; the
  sign-in they perform publishes on its own.
- Step-up succeeding. No session is created and no factor state is news beyond the
  `RecoveryCodeUsed` or `TwoFactorFailed` the attempt itself publishes. Worth revisiting if somebody
  asks for "who elevated what, when".
- A wrong current password on `POST /auth/password`. It is not a sign-in, and reusing `SignInFailed`
  for it would make sign-in counts wrong.

## Secrets

Nothing published carries a password, a TOTP secret, a recovery code, a reset or invitation token or
a refresh token. The unknown-identifier event deliberately does not carry the identifier that was
tried either: people type their password into the user name box, and an audit table outlives every
rotation anyone remembers to perform.

## What changed afterwards

Issue #105, from a review of the publish path.

**The cancellation filter reads the token, not the type.** `catch (Exception ex) when (ex is not
OperationCanceledException)` answers "was this cancelled?" with the exception's type, and
`TaskCanceledException` is what `HttpClient` raises on its own hundred-second timeout and what a
provider raises on a command timeout. A sink posting to an audit API that had stopped answering
therefore failed the sign-in it was auditing - after the refresh row was written and the access
token minted, so the session existed server-side and the caller got a 500 - which is the outage the
absorb-and-log design exists to survive. The filter is now
`|| !cancellationToken.IsCancellationRequested`, the form `HibpPasswordValidator` already used for
the same question. The two notifier catches in `PasswordAccountService` had it too, and there a
timing-out relay put back the 500-for-a-real-address, 204-for-an-unknown-one oracle those catches
exist to erase.

**Sinks are built inside the try.** `IEnumerable<IAuthenticationEventSink>` is materialised by
dependency injection when the publisher is resolved, which is before any request reaches
`PublishAsync`, so a sink whose constructor validated a connection string and found it wrong failed
every request through the endpoints that resolve a publisher. The publisher now takes
`IEnumerable<AuthenticationEventSinkRegistration>` - a type and a factory, neither of which
constructs anything - and calls the factory inside the same try that already caught `HandleAsync`.
A consumer resolving `IAuthenticationEventSink` themselves still gets the sink, and the sink is
still scoped, so it is built once per request and only if an event is published.

**`EmailChanged` exists.** `VerifyEmailAsync` moved the login identifier, the normalized identifier
and the profile address and published nothing, so an audit table fed by a sink held a row for every
password change and lockout and none for the change that moves where every later reset link and
magic link is sent. It carries `PreviousEmail` and `Email`, because the old address is the half that
cannot be read off the account afterwards. `RequestEmailChangeAsync` still publishes nothing, for
the reason beginning an enrolment does not: until the link is redeemed the account is unchanged.

**Four publish sites had no test.** The two in `CompleteStepUpAsync` and the two in
`TwoFactorService.DisableAsync` could all be deleted with both suites green. They have Core tests
now, each watched failing with its own site removed.
