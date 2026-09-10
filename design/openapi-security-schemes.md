# OpenAPI security schemes: what was decided and why

Issue #63. The sample carried thirty-five lines of document and operation transformers under a
comment reading "copy this into your own application", and `auth-analysis.md` records where that
ends: one consumer's copy hardcodes Keycloak's `/protocol/openid-connect/auth` while the deployment
runs Pocket ID, so its Authorize button points at an issuer that has never existed there.

Six decisions in it were not obvious - the first four from that issue, the last two from #94, which
found that two of them were wrong. They are here rather than in the docs because a consumer does not
need them and the next person changing this file does.

## 1. A package of its own, not a reference from `Toamaisutaa.AspNetCore`

`Microsoft.AspNetCore.OpenApi` is a package, not part of the shared framework. Referencing it from
`Toamaisutaa.AspNetCore` would put it in the dependency graph of every application using this
library, including the ones that document themselves with Swashbuckle, with NSwag, or not at all -
and the security half is the only thing they would gain from it.

`Toamaisutaa.OpenApi` depends on `Toamaisutaa.Abstractions` alone, which means it also works in an
application that never calls `AddToamaisutaaBearer` and authenticates some other way. One public
type, `ToamaisutaaOpenApiExtensions`, holding `AddToamaisutaaOpenApi` and
`AddToamaisutaaSecuritySchemes`.

## 2. The OAuth2 URLs are read from the discovery document, not derived from the authority

The issue says the URLs "come from `Oidc:Authority`", and the shortest reading of that is string
concatenation. That is the exact bug the issue cites: `authority + "/protocol/openid-connect/auth"`
is right for Keycloak and wrong for Authentik, Pocket ID, Okta and Entra, and it fails quietly -
the document generates, the button appears, and it points nowhere.

So the transformer fetches `{authority}/.well-known/openid-configuration` and reads
`authorization_endpoint` and `token_endpoint` out of it. This matches requirement 8 of
`auth-analysis.md` ("everything comes from the discovery document") and the bearer handler beside
it, which discovers rather than assumes for the same reason.

Consequences accepted:

- **A network call while the document is generated.** Bounded at five seconds, and the document is
  read by a person opening a page, not on a hot path.
- **~~No cache.~~** Superseded - see section 5.
- **The issuer being down must not break the document.** `HttpRequestException`,
  `OperationCanceledException` and `JsonException` leave the `OAuth2` scheme out, keep the rest of
  the document exactly as it was, and log one line naming the address and the reason. The `Bearer`
  scheme still works, so a token can still be pasted in.
- **`InternalAuthority` is used for the fetch**, like the bearer handler's metadata address: a
  container reaches its issuer at an address the browser never sees. The endpoints inside the
  document were assumed to be the issuer's public ones either way - see section 6 for why that
  assumption did not hold and what replaced it.

### The named client, and the three duplicated lines

The fetch uses `ToamaisutaaDefaults.DiscoveryHttpClientName`, the client the discovery health check
already reaches the same document with, so a proxy or a private certificate authority is configured
once for both. Its own name was the first version of this, and it made a consumer configure the same
handler twice for two fetches of the same URL.

The address formula is duplicated rather than shared: `Toamaisutaa.OpenIdConnect` has it in
`DiscoveryAddress`, and referencing that package from here would put JwtBearer in the dependency
graph of a documentation package. Three lines is the cheaper of the two.

## 3. Two requirements, not one requirement naming two schemes

`document.Security` is a list, and the list is an OR while a single requirement holding two schemes
is an AND. Written the other way round, the document would say a caller must present a locally
issued token *and* an identity provider one, which is not a thing anybody can do. One token gets in,
and which issuer minted it is exactly what this API does not care about.

## 4. The plaintext rule is restated, and is nearly unreachable

`RequireHttpsMetadata` is honoured for this fetch as well. With `AddToamaisutaaBearer` registered
the branch cannot be hit - the JwtBearer handler throws on the first request through the
authentication middleware, so there is no document to generate - but this package stands alone, and
in that composition an http authority with the default settings would otherwise have its
authorization URL fetched over plaintext and rendered as a button people type an identity provider
password into.

That is why `OpenApiDocumentHttpTests.Issuer_metadata_over_plaintext_is_refused_unless_the_deployment_says_otherwise`
builds its own minimal host instead of using `TestApp`: the branch is only reachable in the
composition that has no bearer registration, and a test that cannot reach the branch it names is
worse than no test.

## 5. The discovery answer is cached after all, for five minutes

Issue #94. "No cache" above was decided for a fetch that happens "when somebody opens an API
explorer", which is true of the sample's development-only mapping and was not true of the mapping the
docs handed out: `app.MapOpenApi().AllowAnonymous()` with no environment guard. The document
transformer runs on every request for `/openapi/v1.json`, so an unauthenticated caller in a loop set
the rate at which this process asked the identity provider for its metadata, from a source the
issuer's own rate limiting sees as one trusted service. The second half was worse than the first:
while the issuer was down, every request for the document waited the full five-second discovery
timeout.

`ToamaisutaaDiscoveryHealthCheckOptions.RefreshInterval` exists for the same reason one package over,
so the interval matches it - five minutes, and not configurable here until somebody needs it to be. A
`SemaphoreSlim` collapses concurrent misses onto one fetch, because the load a cache is here to bound
arrives in parallel rather than in sequence.

Two decisions inside it:

- **A failure is cached too.** Otherwise an issuer outage still costs five seconds per reader, which
  was half the problem. The price is that the `OAuth2` scheme can stay out of the document for up to
  the interval after the issuer comes back, and the `Bearer` scheme carries the document meanwhile.
- **The cache is a captured instance, not a DI singleton.** `AddToamaisutaaSecuritySchemes` takes
  `OpenApiOptions` and has no service collection to register into, and the alternative - registering
  it only from `AddToamaisutaaOpenApi` and falling back to an uncached fetch - would mean the two
  entry points quietly differed. One instance per registration, captured by the transformer, is the
  same lifetime with none of that.

The docs and the package README now show the mapping guarded by `IsDevelopment` the way the sample
already mapped it. The cache is the fix; the guard is what stops the document being published by
accident in the first place.

## 6. Endpoints discovered under `InternalAuthority` are moved onto `Authority`

Section 2's last bullet asserted that "the endpoints inside the document are the issuer's public ones
either way". That is a statement about how an issuer is configured, not a property of discovery.
Keycloak with no `KC_HOSTNAME` builds its endpoint URLs from the request's Host header, so fetching
over `http://keycloak:8080` yields `http://keycloak:8080/...` endpoints - written verbatim into the
document as the Authorize button's `authorizationUrl`, and the browser cannot resolve `keycloak`.
Copying the bearer handler's metadata address was right; copying its confidence in what comes back
was not, because that handler consumes only JWKS and an issuer string it pins separately, while this
document consumes two URLs a browser has to resolve.

An endpoint whose origin is the internal authority's, and whose path is under the internal
authority's path, is moved onto `Oidc:Authority` keeping the path suffix. `Authority` is the right
destination rather than a guess: it is what `ToamaisutaaClientConfigurationProvider` already hands
the SPA, so the Authorize button and the SPA point at the same issuer.

Anything else is left exactly as the issuer gave it. The issue proposed dropping the `OAuth2` scheme
with a warning when an endpoint is not under the internal authority, and that is worse than doing
nothing: an issuer whose authorization endpoint lives on a login domain of its own is ordinary, that
URL is already browser-resolvable, and refusing to emit a scheme would break deployments that work
today to guard against a case indistinguishable from them. Only what is provably the internal address
is rewritten.

## Testing

The discovery fetch resolves back into the test host: the named `HttpClient` gets the `TestServer`'s
own handler as its primary handler, and a test serves issuer metadata from an ordinary route. No
network, no identity provider, and the real fetch-and-parse path is the one under test rather than a
stub of it. An address with no route answers a refusal instead of a document, which is the same
branch as an issuer that is not there at all.

Sections 5 and 6 are tested from that same host. `Oidc:InternalAuthority` points at a route this host
serves, the metadata that route answers with carries the internal address, and the assertion reads
`authorizationUrl` off the raw document - both the endpoint that gets moved and the ones that must
not be. The caching test counts how many times its metadata route was hit across three reads of the
document, then advances `TestApp.Time` past the interval and counts again; with the cache removed it
counts three, which is the finding.
