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
| `Oidc:UserInfoCacheDuration` | `00:05:00` | Cached per subject and grant, per issuer and audience |
| `Oidc:ShareUserInfoCacheAcrossInstances` | `false` | Lets the userinfo cache use your `IDistributedCache` as a second level |
| `Oidc:Scope` | `openid profile email roles` | Served to the client |
| `Oidc:RedirectUri` | derived | Falls back to `PublicUrl`, then the request origin |
| `Oidc:PostLogoutRedirectUri` | `RedirectUri` | |
| `Oidc:PublicUrl` | | Used to derive the two above. Set it in production: without it the redirect URI comes from the request's Host header, which the caller controls, and a warning is logged once, on the first request, outside Development. Every response built from `IToamaisutaaClientConfigurationProvider`, on `/api/app` or an endpoint of your own, is sent `Cache-Control: no-store` |
| `Oidc:AdminRole` | | Registers the `Toamaisutaa.Admin` policy when set, which is also what maps the [admin provisioning endpoints](/provisioning-accounts#the-three-admin-endpoints-need-an-admin-role) |
| `Oidc:RequireAdminRoleGlobally` | `false` | Makes every endpoint that is not anonymous admin-only - a bare `[Authorize]`, one naming a policy or roles of its own, and this package's own. Enforced in the `IAuthorizationMiddlewareResultHandler`, wrapping any registered before `AddToamaisutaaAuthorization`; register yours earlier, since one registered after replaces it |
| `Oidc:QueryToken:IncludePaths:0` | | Path prefixes where `?access_token=` is honoured, for SignalR |
| `Oidc:QueryToken:ExcludePaths:0` | | Carved back out of the above |
| `Oidc:HealthCheck:RefreshInterval` | `00:05:00` | How long the health check trusts a successful fetch, and remembers a failed one |
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

Results are cached per subject and grant (the token's scopes and client) for
`Oidc:UserInfoCacheDuration`, because userinfo answers per grant; a token that names no scopes is
cached on its own. The cache goes through
[`HybridCache`](https://learn.microsoft.com/aspnet/core/performance/caching/hybrid). Two things
follow from that:

- Requests carrying the same token that arrive together share one userinfo call.
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

It is off by default because the entries decide authorization and carry whatever else your issuer
puts in userinfo, usually an email and a name, as plaintext in a store the package does not own.

The key names the issuer and the audiences this service accepts, so two services against one issuer
sharing an unprefixed Redis do not read each other's entries even when they share the store.

## Health check

A wrong `Oidc:Authority` or an unreachable `Oidc:InternalAuthority` is otherwise invisible until the
first request carrying a token answers 401. `AddToamaisutaaHealthChecks()` turns it into a failing
probe at deploy time instead.

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

Degraded keeps the instance in rotation, because a handler that already loaded the document keeps
validating tokens with the keys it holds. Set `Oidc:HealthCheck:DegradedFor` to `00:00:00` to report
unhealthy on the first failure.

The check uses its own client and its own copy of the document, not the bearer handler's. A 200 that
is not a discovery document - a proxy answering with a sign-in page - counts as a failure.

It is registered as `toamaisutaa-oidc-discovery` and tagged `toamaisutaa`, `oidc` and `ready`, so a
readiness endpoint can select it without naming it:

```csharp
app.MapHealthChecks("/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") })
    .AllowAnonymous();
```

A successful or failed fetch is remembered for `Oidc:HealthCheck:RefreshInterval`, and probes in
between - including ones that arrive together - are answered from it rather than each reaching the
issuer.

To put a proxy or a handler on the probe without touching the path a signed-in request takes,
configure the named client `toamaisutaa-discovery`.

## Claims mapping

The default mapper reads `sub`, `preferred_username`, `email`, `name` and `picture`, with the
display name falling back `name` → `preferred_username` → `email`.

Claim types are the raw JWT names. Inbound claim mapping is **off and not configurable**, so
`Oidc:NameClaim` and `Oidc:RoleClaim` name claims exactly as the issuer wrote them, never the
WS-Federation URIs .NET would otherwise remap them to.

To map claims differently, register your own `IClaimsProfileMapper` before
`AddToamaisutaaProvisioning()`. `DefaultClaimsProfileMapper` is public so you can delegate to it for
the parts you do not care about.

## Deciding who gets a local row

Provisioning creates a row the first time a subject is seen. Two seams sit on that path.

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

**`IExternalLoginProvisioner` is the whole read-or-create step**, if you want to own the sequence.
Most needs are met by `IClaimsProfileMapper` for the fields and `IProvisioningPolicy` for the
decision.

Linking a second identity provider to an existing user raises
`ExternalLoginConflictException` when that (provider, subject) pair already belongs to somebody
else. Handle it, or it surfaces as a 500.

## SignalR and WebSockets

Browsers cannot set an `Authorization` header on a WebSocket handshake, so SignalR clients pass the
token as a query parameter. Honour it only where it is needed:

```json
{ "Oidc": { "QueryToken": { "IncludePaths": ["/hubs"], "ExcludePaths": ["/hubs/node"] } } }
```

An empty `IncludePaths` means the feature is off; there is no separate switch. `ExcludePaths` is for
a hub that authenticates something other than an OIDC token on its own.

## Migrating from a hand-rolled JwtBearer block

Three behaviours are likely to differ from what you have:

- **`MapInboundClaims` is off.** Claim types stay as the issuer wrote them (`sub`,
  `preferred_username`, `roles`). Check anything that reads `ClaimTypes.*` directly.
- **Audience validation is on by default.** If your tokens' `aud` does not name your API, set
  `Oidc:ValidAudiences` or turn `Oidc:ValidateAudience` off deliberately.
- **ID tokens are refused.** The default audience is the client id, which is also the audience of
  every ID token issued to that client. A token that labels itself with a `typ` claim, as Keycloak
  does, is judged by that label alone - `ID` is refused and `Bearer` accepted, so older Keycloak
  access tokens carrying `nonce` still work. A token with no label is refused when it carries `nonce`
  or `at_hash`. An ID token with none of these cannot be told apart, which is why startup logs a
  warning while `Oidc:ValidAudiences` is empty: set it to your API's own audience where your provider
  lets you.
