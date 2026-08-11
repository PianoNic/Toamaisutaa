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
| `Oidc:UserInfoCacheDuration` | `00:05:00` | Cached per subject |
| `Oidc:Scope` | `openid profile email roles` | Served to the client |
| `Oidc:RedirectUri` | derived | Falls back to `PublicUrl`, then the request origin |
| `Oidc:PostLogoutRedirectUri` | `RedirectUri` | |
| `Oidc:PublicUrl` | | Used to derive the two above |
| `Oidc:AdminRole` | | Registers the `Toamaisutaa.Admin` policy when set |
| `Oidc:RequireAdminRoleGlobally` | `false` | Puts the admin role in the fallback policy |
| `Oidc:QueryToken:IncludePaths:0` | | Path prefixes where `?access_token=` is honoured, for SignalR |
| `Oidc:QueryToken:ExcludePaths:0` | | Carved back out of the above |

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

Results are cached per subject for `Oidc:UserInfoCacheDuration`. Set
`Oidc:FetchClaimsFromUserInfo` to `false` to stop the package calling your issuer at all.

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
