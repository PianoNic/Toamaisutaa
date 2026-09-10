# Metrics

Toamaisutaa publishes counters and one histogram through `System.Diagnostics.Metrics`, on a meter
named `Toamaisutaa`. No package to install and nothing to switch on: the instruments exist as soon
as password login or two-factor is registered, and a meter nobody is listening to costs nothing.

Subscribe to it the way you subscribe to any other meter:

```csharp
builder.Services.AddOpenTelemetry().WithMetrics(metrics => metrics
    .AddMeter(ToamaisutaaDefaults.MeterName)      // "Toamaisutaa"
    .AddAspNetCoreInstrumentation()
    .AddPrometheusExporter());
```

`ToamaisutaaDefaults.MeterName` lives in `Toamaisutaa.Abstractions` and is there so a typo cannot
quietly leave a dashboard empty.

## The instruments

| Name | Kind | Unit | Tags |
|---|---|---|---|
| `toamaisutaa.sign_in.attempts` | counter | `{attempt}` | `result`, `amr` |
| `toamaisutaa.lockouts` | counter | `{lockout}` | |
| `toamaisutaa.two_factor.verifications` | counter | `{verification}` | `source`, `result` |
| `toamaisutaa.refresh_token.reuse_detections` | counter | `{detection}` | |
| `toamaisutaa.rate_limit.rejections` | counter | `{rejection}` | |
| `toamaisutaa.password.verification.duration` | histogram | `s` | `result` |

### Tag values

`result` on a sign-in is the outcome the caller was told, in snake case: `succeeded`,
`unknown_user`, `invalid_password`, `locked_out`, `two_factor_required`, and so on for every member
of `SignInOutcome`.

`amr` is the space-separated RFC 8176 methods the attempt ended up proving - `pwd`, `pwd mfa`,
`pwd otp mfa` - and `none` for an attempt that issued nothing. Summing over `amr` gives you attempts;
summing over `result` gives you sign-ins split by how they were proved.

`source` is which second factor was presented: `otp`, `recovery`, `device` or `passkey`.

`result` on the password histogram is what the hasher answered - `succeeded`, `rehash_needed`,
`failed` - plus `no_credential` for the derivation run against an identifier that does not exist.

## Four things worth knowing before you graph them

**No tag names a person.** No user id, no user name, no address, nothing derived from a credential.
A time series outlives a log line by a long way and gets shared with whoever is on call, so the
dimensions here are all small fixed sets. Which account something happened to is in the logs, where
it can be aged out.

**A refresh is not a sign-in.** Rotating a refresh token does not touch
`toamaisutaa.sign_in.attempts`, or your attempt rate would climb with session length rather than
with traffic. Reuse detection has its own counter, and that one is never routine: every increment
means two parties held the same chain.

**`no_credential` should cost about what `succeeded` costs.** An identifier that does not exist is
made to pay for a full key derivation on purpose, so response time cannot be used to enumerate
accounts. Those two series diverging is the signal that the equalisation has stopped working.

**Only determinate second factors are counted.** A blank code, or a challenge issued against an
enrolment that has since been deleted, never named a source and so never reaches
`toamaisutaa.two_factor.verifications`. Likewise, a sign-in that presents no device token is not a
failed `device` verification.

## What the rate-limit counter covers

`toamaisutaa.rate_limit.rejections` counts the 429s from this package's own limiter on the
unauthenticated password, two-factor and device endpoints. It is deliberately not the framework's
rate limiter - see [customizing local login](/customizing-password-login) - so it does not appear in
`aspnetcore.rate_limiting.*`, and the framework's own counters say nothing about it.
