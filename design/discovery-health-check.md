# Discovery health check: what was decided while implementing it

Issue #72 asked for `AddToamaisutaaHealthChecks()` registering a check that fetches the
`.well-known/openid-configuration` the bearer handler uses, unhealthy on failure and degraded when
the cached document is being served past its refresh interval. That is what shipped. Four decisions
around it were not in the brief and are worth the record.

## It lives in `Toamaisutaa.OpenIdConnect`, and adds no package reference

The issue noted that `Microsoft.Extensions.Diagnostics.HealthChecks` is a `Microsoft.Extensions.*`
package, which under the layering rule would allow `Toamaisutaa.Core`. It went into
`Toamaisutaa.OpenIdConnect` instead, for two reasons:

- The address being probed has to be the address the handler uses. `ConfigureToamaisutaaJwtBearerOptions`
  is what computes it, and both now go through one `DiscoveryAddress` helper. A check in `Core`
  would have had to re-derive it from the same options and could drift from the handler silently -
  which is the specific failure of a health check that goes green against something nobody validates
  tokens with.
- `Microsoft.Extensions.Diagnostics.HealthChecks`, its `.Abstractions`, and `Microsoft.Extensions.Http`
  are all in the `Microsoft.AspNetCore.App` shared framework, which this project already has a
  `FrameworkReference` to. So the feature costs zero new package references. In `Core` it would have
  cost two.

`Directory.Packages.props` is untouched.

## The check does not compare the document's issuer against `Oidc:Authority`

This looked like the single most valuable thing it could report, since a trailing slash between
`Oidc:Authority` and the issuer's own `iss` is exactly the shape of "a wrong authority shows up as a
401". It is not, and the reason is in `JwtBearerHandler`: before validating, it concatenates
`configuration.Issuer` from the discovery document onto `TokenValidationParameters.ValidIssuers`. A
token carrying the document's issuer therefore validates whether or not it matches `Oidc:Authority`,
and reporting the mismatch as unhealthy would fail a probe for an application that works.

The discovered issuer is put in the check's `data` and named in its description instead, so an
operator reading the report sees which issuer answered and can spot a wrong one without the check
having to guess that it is wrong.

`Oidc:Authority` is still served to the SPA, so a mismatch there does break the browser's
authorization-code flow. That is a different check, on a different thing, and is not this one.

## A plaintext metadata address is deliberately not reported

The first draft reported unhealthy when `Oidc:RequireHttpsMetadata` was on and the address was
`http://`, on the grounds that the handler refuses to fetch it. Writing the test showed the branch is
unreachable: `JwtBearerPostConfigureOptions.PostConfigure` throws while the handler's options are
being built, `AuthenticationMiddleware` runs before endpoint routing, and the health endpoint
therefore answers 500 like every other route. The test asserting 503 got an
`InvalidOperationException` instead.

The guard and both its tests were removed. A note in `DiscoveryHealthCheck`'s remarks says why, so it
does not get added back.

## No issuer configured is unhealthy, not healthy

An application that only issues its own tokens has no `Oidc:Authority` and nothing here to probe.
Reporting healthy would be the friendlier answer and is the wrong one: somebody who called
`AddToamaisutaaHealthChecks()` believes there is an issuer, and a mistyped configuration key would
otherwise be reported as fine forever. The message names both keys it looked at and says to drop the
call if the application really has no issuer.

## `Oidc:HealthCheck`, not a section of its own

`RefreshInterval` and `Timeout` are nested under the existing `Oidc` section the way `QueryToken`
already is, so nothing new has to be bound and `AddToamaisutaaHealthChecks()` takes no arguments.

`RefreshInterval` is the check's own, not the handler's. `ConfigurationManager.AutomaticRefreshInterval`
defaults to twelve hours, and a probe that reaches the issuer twice a day would tell an operator
nothing at deploy time. Five minutes is short enough to be current and long enough that a fleet of
replicas being probed every few seconds does not become load on the issuer.
