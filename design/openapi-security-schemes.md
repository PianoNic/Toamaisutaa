# OpenAPI security schemes: what was decided and why

Issue #63. The sample carried thirty-five lines of document and operation transformers under a
comment reading "copy this into your own application", and `auth-analysis.md` records where that
ends: one consumer's copy hardcodes Keycloak's `/protocol/openid-connect/auth` while the deployment
runs Pocket ID, so its Authorize button points at an issuer that has never existed there.

Four decisions in it were not obvious. They are here rather than in the docs because a consumer does
not need them and the next person changing this file does.

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
- **No cache.** A cache here would be a second lifetime to reason about for a fetch that happens
  when somebody opens an API explorer. If that ever becomes a problem, `IMemoryCache` is already in
  the container.
- **The issuer being down must not break the document.** `HttpRequestException`,
  `OperationCanceledException` and `JsonException` leave the `OAuth2` scheme out, keep the rest of
  the document exactly as it was, and log one line naming the address and the reason. The `Bearer`
  scheme still works, so a token can still be pasted in.
- **`InternalAuthority` is used for the fetch**, like the bearer handler's metadata address: a
  container reaches its issuer at an address the browser never sees. The endpoints inside the
  document are the issuer's public ones either way, which is what the browser needs.

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

## Testing

The discovery fetch resolves back into the test host: the named `HttpClient` gets the `TestServer`'s
own handler as its primary handler, and a test serves issuer metadata from an ordinary route. No
network, no identity provider, and the real fetch-and-parse path is the one under test rather than a
stub of it. An address with no route answers a refusal instead of a document, which is the same
branch as an issuer that is not there at all.
