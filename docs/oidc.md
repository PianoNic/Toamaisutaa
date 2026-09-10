# OIDC bearer validation

The recommended path. Your client runs the authorization-code flow with PKCE; Toamaisutaa validates
the access token it sends.

Nothing constructs a provider-specific URL. Authorization, token and userinfo endpoints all come
from the issuer's discovery document, which is what makes Keycloak, Authentik, Pocket ID, Okta and
Entra a configuration change rather than a code change.

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
```

## Configuration

Everything binds from the `Oidc` section.

| Key | Default | Notes |
|---|---|---|
| `Oidc:Authority` | | The issuer as your tokens see it |
| `Oidc:InternalAuthority` | `Authority` | Where this process reaches the issuer for discovery, when that differs - a container on the same Docker network, a service behind a proxy |
| `Oidc:ClientId` | | Also the default valid audience |
| `Oidc:RequireHttpsMetadata` | `true` | |
| `Oidc:ValidateIssuer` | `true` | |
| `Oidc:ValidateAudience` | `true` | |
| `Oidc:ValidAudiences:0` | `[ClientId]` | |
| `Oidc:NameClaim` | `name` | |
| `Oidc:RoleClaim` | `roles` | Set to `groups` for Pocket ID, Authentik and Entra |
| `Oidc:FetchClaimsFromUserInfo` | `true` | Reads roles from userinfo when the access token omits them |
| `Oidc:UserInfoCacheDuration` | `00:05:00` | Cached per subject, per issuer and audience |
| `Oidc:ShareUserInfoCacheAcrossInstances` | `false` | Lets the userinfo cache use your `IDistributedCache` as a second level |
| `Oidc:Scope` | `openid profile email roles` | Served to the client |
| `Oidc:RedirectUri` | derived | Falls back to `PublicUrl`, then the request origin |
| `Oidc:PostLogoutRedirectUri` | `RedirectUri` | |
| `Oidc:PublicUrl` | | Used to derive the two above |
| `Oidc:AdminRole` | | Registers the `Toamaisutaa.Admin` policy when set, which is also what maps the [admin provisioning endpoints](/provisioning-accounts#the-three-admin-endpoints-need-an-admin-role) |
| `Oidc:RequireAdminRoleGlobally` | `false` | Puts the admin role in the fallback policy |
| `Oidc:QueryToken:IncludePaths:0` | | Path prefixes where `?access_token=` is honoured, for SignalR |
| `Oidc:QueryToken:ExcludePaths:0` | | Carved back out of the above |
| `Oidc:HealthCheck:RefreshInterval` | `00:05:00` | How long the health check trusts a successful fetch |
| `Oidc:HealthCheck:Timeout` | `00:00:05` | How long one fetch is given before it counts as unreachable |
| `Oidc:HealthCheck:DegradedFor` | `00:15:00` | How long after the last successful fetch an unreachable issuer stays degraded |

## The role claim is the thing that catches people

Issuers disagree about where group membership lives. Keycloak publishes `roles`; Pocket ID,
Authentik and Entra publish `groups`. Reading the wrong one returns 403 on every request while the
token itself is perfectly valid, which is a genuinely miserable afternoon.

Two things help:

- `Oidc:RoleClaim` moves where the check looks.
- Every 403 logs which claim was read, what the principal actually carried there, and every claim
  type present. If you are staring at an empty 403, that log line is the whole answer.

## Roles the token does not carry

Pocket ID, Okta and Entra keep group membership out of the access token to bound its size. When the
configured role claim is missing, Toamaisutaa asks the issuer's userinfo endpoint once, flattens the
response - arrays become one claim per entry, which is the only shape that lets a role check match a
single group - and merges what it finds.

A userinfo endpoint that is down logs a warning and lets the token's own claims decide. It never
turns a valid login into a 500.

Results are cached per subject for `Oidc:UserInfoCacheDuration`, through
[`HybridCache`](https://learn.microsoft.com/aspnet/core/performance/caching/hybrid). Two things
follow from that:

- Requests carrying the same token that arrive together share one userinfo call. A page reload
  against a cold cache fires a dozen requests before any of them has answered, and that used to be
  a dozen calls to your issuer.
- Every instance fetches once. Sharing the entry between them takes
  `Oidc:ShareUserInfoCacheAcrossInstances`, below.

`AddToamaisutaaBearer` registers `HybridCache` itself. Calling `AddHybridCache` yourself, with your
own options, keeps working: the registration is additive and your options still apply.

A failed read is never cached, so an issuer that comes back up is used on the very next request.

Set `Oidc:FetchClaimsFromUserInfo` to `false` to stop the package calling your issuer at all.

### Sharing the cache between instances

`Oidc:ShareUserInfoCacheAcrossInstances` is `false`, and registering an `IDistributedCache` does not
change that on its own. Turn it on and the entries use your Redis or SQL Server as a second level,
so a scaled-out deployment warms each subject once rather than once per instance.

It is a switch rather than the default because of what these entries are. They decide authorization,
and they carry whatever else your issuer puts in userinfo, which is usually an email and a name. On
the way in, they become a plaintext value in a store the package does not own, next to every other
tenant of it. Deciding that is fine is a reasonable thing to do, and it is not something the package
can decide on your behalf from the presence of a Redis connection string.

The key names the issuer and the audiences this service accepts, so two services against one issuer
sharing an unprefixed Redis do not read each other's entries even when they share the store.

## Health check

A wrong `Oidc:Authority` or an unreachable `Oidc:InternalAuthority` is invisible until the first
request carrying a token, and then it is a 401 - which reads as "my login is broken" rather than "the
issuer was never reachable from this container". `AddToamaisutaaHealthChecks()` turns it into a
failing probe at deploy time instead.

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);
builder.Services.AddToamaisutaaHealthChecks();

// Anonymous, and it has to be - the fallback policy would otherwise answer 401, and an
// orchestrator reads that as a failing probe no matter how healthy the issuer is.
app.MapHealthChecks("/health").AllowAnonymous();
```

The check fetches the same `.well-known/openid-configuration` the bearer handler uses, including
`Oidc:InternalAuthority` when discovery is pointed somewhere other than the public issuer:

| Result | When | Status code from `MapHealthChecks` |
|---|---|---|
| Healthy | The document was fetched, and carries an `issuer` and a `jwks_uri` | 200 |
| Degraded | The issuer stopped answering, and this process fetched the document less than `Oidc:HealthCheck:DegradedFor` ago | 200 |
| Unhealthy | The issuer stopped answering and the last fetch is older than that, no document has ever been fetched, or no issuer is configured at all | 503 |

Degraded rather than unhealthy for a recent fetch is the point of the distinction. A handler that
loaded the document keeps validating tokens against the keys it already holds, so taking the
instance out of rotation would break something that still works - but you want to know before the
issuer rotates its signing keys.

That answer is bounded, because degraded is a 200 and a 200 keeps the instance in the load balancer.
`Oidc:HealthCheck:DegradedFor` is how long the last successful fetch counts for; past it the check
reports unhealthy, on the grounds that an issuer nobody here has reached for a quarter of an hour is
no longer evidence of anything. Set it to `00:00:00` to report unhealthy on the first failure.

What the check reports is what the check itself fetched. It has its own client and its own refresh
interval, and cannot see the document the bearer handler holds - that one lives in the handler's
`ConfigurationManager` and is loaded lazily on the first request carrying a token, so a process that
has only served anonymous traffic has none at all.

A 200 that is not a discovery document counts as a failure. A reverse proxy that has lost its route
answers a sign-in page with one, and the handler needs the keys rather than the status.

It is registered as `toamaisutaa-oidc-discovery` and tagged `toamaisutaa`, `oidc` and `ready`, so a
readiness endpoint can select it without naming it:

```csharp
app.MapHealthChecks("/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") })
    .AllowAnonymous();
```

A successful fetch is trusted for `Oidc:HealthCheck:RefreshInterval`, and probes in between are
answered from it. Readiness probes run every few seconds across every replica, and fetching on each
one would put a steady load on the issuer for an answer that changes rarely.

To put a proxy or a handler on the probe without touching the path a signed-in request takes,
configure the named client `toamaisutaa-discovery`.

## Claims mapping

The default mapper reads `sub`, `preferred_username`, `email`, `name` and `picture`, with the
display name falling back `name` → `preferred_username` → `email`.

Claim types are the raw JWT names. Inbound claim mapping is **off and not configurable**. .NET's
default remaps claims to WS-Federation URIs, which leaves `Oidc:NameClaim` and `Oidc:RoleClaim`
naming raw JWT claims that no longer exist on the principal - a `NameClaimType` that quietly matches
nothing. Turning it off everywhere means one set of names, the issuer's.

To map claims differently, register your own `IClaimsProfileMapper` before
`AddToamaisutaaProvisioning()`. `DefaultClaimsProfileMapper` is public so you can delegate to it for
the parts you do not care about.

## Deciding who gets a local row

Provisioning creates a row the first time a subject is seen. Two seams sit on that path, and both
are worth knowing before you decide you need to fork something.

**`IProvisioningPolicy` answers "should this subject get an account at all, and which one".** The
default creates one for anybody your issuer vouched for. Replace it to refuse subjects outside a
tenant, to require a claim before an account exists, or to link an incoming external identity to a
local user you matched some other way:

```csharp
builder.Services.AddSingleton<IProvisioningPolicy, YourProvisioningPolicy>();
builder.Services.AddToamaisutaaProvisioning();
```

It returns a `ProvisioningDecision`, so refusing is a decision the pipeline understands rather than
an exception you throw from inside a mapper.

**`IExternalLoginProvisioner` is the whole read-or-create step**, if the policy seam is not enough
and you want to own the sequence. Rarely the right one to reach for - most of what people want is
`IClaimsProfileMapper` for the fields and `IProvisioningPolicy` for the decision.

Linking a second identity provider to an existing user raises
`ExternalLoginConflictException` when that (provider, subject) pair already belongs to somebody
else, which is the case worth handling deliberately rather than letting surface as a 500.

## SignalR and WebSockets

Browsers cannot set an `Authorization` header on a WebSocket handshake, so SignalR clients pass the
token as a query parameter. Honour it only where it is needed:

```json
{ "Oidc": { "QueryToken": { "IncludePaths": ["/hubs"], "ExcludePaths": ["/hubs/node"] } } }
```

An empty `IncludePaths` means the feature is off - there is no separate switch, so "enabled but
scoped to nothing" cannot happen. `ExcludePaths` exists for a hub that authenticates something other
than an OIDC token on its own.

## Migrating from a hand-rolled JwtBearer block

Two behaviours are likely to differ from what you have:

- **`MapInboundClaims` is off.** Claim types stay as the issuer wrote them (`sub`,
  `preferred_username`, `roles`). Check anything that reads `ClaimTypes.*` directly.
- **Audience validation is on by default.** If your tokens' `aud` does not name your API, set
  `Oidc:ValidAudiences` or turn `Oidc:ValidateAudience` off deliberately.
