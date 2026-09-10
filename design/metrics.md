# Metrics: what was decided and why

Issue #68. No `Meter` and no `ActivitySource` existed anywhere in the shipping code, and
`PasswordRateLimiter` said out loud that owning the limiter cost it the framework's metrics. The
issue asked for one meter named `Toamaisutaa` with counters for sign-in outcomes, lockouts,
two-factor verifications, refresh reuse and rate-limit rejections, plus a histogram for password
verification time, using `System.Diagnostics.Metrics` and no package.

What follows is the part a consumer does not need and the next person changing `ToamaisutaaMetrics`
does. The consumer-facing half is in `docs/metrics.md`.

## 1. The meter is constructed, not taken from `IMeterFactory`

`IMeterFactory` is the recommended way to get a meter in a hosted application, and it is in
`Microsoft.Extensions.Diagnostics.Abstractions`. `Toamaisutaa.Core` references `Abstractions`,
`Microsoft.Extensions.Options`, `Logging.Abstractions`, `Hosting.Abstractions` and
`DependencyInjection.Abstractions` and nothing else, because the layering rule says it has to stay
usable from a console app. `Meter` itself is in the shared framework and costs nothing, so
`ToamaisutaaMetrics` news one up and disposes it. The issue asked for exactly this.

What is given up: the factory's cache keyed by name and scope, which matters when several
independent components want the same meter. Nothing else in this package publishes to
`Toamaisutaa`, and `TryAddSingleton` means one instance per container either way.

## 2. `ToamaisutaaDefaults.MeterName` is public, `ToamaisutaaMetrics` is not

A metrics pipeline subscribes by string. `AddMeter("Tomaisutaa")` compiles, runs, and produces an
empty dashboard with no error anywhere, which is a bad failure to ship when a constant costs one
line. That is the whole justification for the one new public member.

The class stays internal. It is called from four files inside the package and by nothing outside it;
making it public would freeze every instrument name and every method signature as a contract, for a
type a consumer never resolves.

## 3. A refresh is not a sign-in attempt

`PasswordSignInService.RefreshAsync` returns the same `SignInResult` type as `SignInAsync`, and it
was tempting to count both through the one `Failed` helper they share. Folding them together makes
`toamaisutaa.sign_in.attempts` rise with session length rather than with traffic: an application
with a fifteen-minute access token would report four "sign-ins" an hour per idle browser tab.

So refusals on the sign-in path go through a new `Refused` helper that counts, and the refresh path
keeps the old static `Failed` that does not. Refresh has its own counter for the one event on that
path worth a series of its own - reuse detection, which is never routine.

There is a test named for this (`ARefreshIsNotCountedAsASignInAttempt`), because the two helpers
differ by one line and nothing else would notice them being merged back.

## 4. `amr` is `none` for a refusal, not the methods proved so far

A refused attempt could reasonably report what it had got through - `TwoFactorRequired` did prove a
password. Reporting `pwd` there would make the same series mean two different things, and
`sum by (amr)` would then double-count an enrolled user's sign-in: once as `pwd` when the password
landed and once as `pwd otp mfa` when the code did.

One value for "issued nothing" keeps the counter additive. Summing over `amr` gives attempts;
summing over `result` gives sign-ins split by how they were proved.

## 5. Only a determinate second factor is counted

`TwoFactorVerifier.VerifyAsync` refuses a blank code and a challenge whose enrolment has since been
deleted before it ever decides whether it is looking at a TOTP code or a recovery code. Those
refusals have no `source`, and inventing one - `unknown`, say - would put attempts in the series that
nobody made and would make the recovery-code rate look wrong.

The device factor is counted from `PasswordSignInService` rather than from inside
`TrustedDeviceGate`, which has six ways to refuse and returns `NotTrusted` for all of them,
including "nobody presented a token". The caller is the only place that can tell those apart, and
the guard there is the same `IsNullOrWhiteSpace` check the gate opens with.

## 6. Result values are spelled out rather than taken from `Enum.ToString`

`SignInOutcome.ToString()` would be free and would follow the enum for ever, including through a
rename. A rename is a source-compatible change to a public enum and a breaking change to somebody's
dashboard, and the second one would ship silently. The switch in `Describe` costs eighteen lines and
makes the series names something a reviewer can see changing.

The discard arm falls back to the member name, so an outcome added and not named here still records
rather than throwing on a sign-in.

## 7. The equalising derivation is timed too

`DummyPasswordHash.Verify` exists so an unknown identifier costs what a real one costs, and nothing
in the suite checks that it still does - the property is about wall-clock time, which a unit test is
the wrong instrument for. Tagging it `no_credential` on the same histogram makes the two series
directly comparable, and them diverging is the signal that the equalisation has stopped working.

This is the one instrument here that is not just an operational counter but a check on a security
property, which is why it earns the extra tag value.

## 8. Lockouts are counted at the transition, not per failed attempt

`metrics.LockedOut()` fires only when `LockoutPolicy.IsLockedOut` answers true immediately after a
`RegisterFailure` that did not follow one - so it counts accounts crossing the threshold, not
attempts made against a locked account. Asked of the policy rather than inferred from
`FailedAttemptCount`, because the policy owns both the threshold and the window reset and clears the
counter when it locks.

Both call sites are covered: a wrong password at sign-in, and a wrong code at step-up. Step-up
counting against the same lockout is deliberate and already documented; the metric follows it.

No tags. Which of the two paths locked the account is in the log line beside it, and the series is
more useful as a single number an alert can be pointed at.

## 9. `InternalsVisibleTo` for `Toamaisutaa.AspNetCore.Tests`

Every `TestApp` in the HTTP suite publishes a meter called `Toamaisutaa`, and the suite runs its
tests in parallel. A listener filtering by meter *name* would count whichever other host happened to
be signing someone in at the time - a test that passes, fails, or flakes for reasons unconnected to
what it is named after, which is precisely the failure mode `CLAUDE.md` warns about.

Filtering by meter *instance* fixes it, and reaching the instance means resolving `ToamaisutaaMetrics`
from the host's container. `Toamaisutaa.OpenIdConnect` already does the same for the same suite.
