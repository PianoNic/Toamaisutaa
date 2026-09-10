# Userinfo claims on HybridCache

Issue #65. `UserInfoClaimsEnricher` cached through `IMemoryCache`; it now caches through
`Microsoft.Extensions.Caching.Hybrid`. Three decisions in that change were not obvious, so they are
written down here rather than left to be rediscovered from the diff.

## A failed read leaves the factory as an exception

`IMemoryCache` let the enricher decide, after the call, whether the result was worth storing: a
userinfo endpoint answering 503 returned an empty claim set and never reached `cache.Set`. The next
request retried.

`GetOrCreateAsync` stores whatever the factory returns. Returning `[]` from a 503 would therefore
cache "this user has no groups" for the whole `UserInfoCacheDuration`, and a five-minute blip at the
issuer would become five minutes of 403s that outlive it - the exact failure the fail-open exists to
prevent, arriving later and reading as a policy bug.

HybridCache has no "do not store this one" for a value the factory has already produced, so the
non-cacheable outcome leaves as a private `UserInfoUnavailableException` that `EnrichAsync` catches
and drops. It is logged with its status where it is raised, so the catch is silent rather than
double-logging. Nothing outside the class can see the type.

This also depends on HybridCache propagating a factory exception unwrapped, including to callers
joined to an in-flight call. It does, and
`A_userinfo_endpoint_that_cannot_be_reached_leaves_the_token_claims_deciding` is the test that says
so - the existing `catch` filter names `HttpRequestException` by type, and a wrapped exception would
walk straight past it into a 500.

## The key stays keyed on the subject

The issue text says "key stays the hash of the access token". The code it describes has keyed on the
subject since phase 2, with a SHA-256 of the token only as the fallback for a principal that somehow
carries no `sub`. Keeping the token hash as the primary key would mean a fresh userinfo call after
every token refresh, for claims that did not change. Left as it was.

## Cached values are a record, not a tuple

`ClaimsJsonFlattener` returns `(string Type, string Value)` tuples, which is the right shape to read
and the wrong one to store: a HybridCache value can be serialised into a consumer's
`IDistributedCache`, and System.Text.Json writes a ValueTuple's fields as `{}`. Hence
`UserInfoClaim`, internal, which exists for the serialiser and nothing else.

## What consumers get and do not get

`AddToamaisutaaBearer` calls `AddHybridCache`, and every consumer gets the in-memory first level and
the stampede protection, which is the half that matters on a cold start. The second level is a
switch, for the reason below.

## The second level is opt-in, and the key names the deployment (issue #91)

Corrects both of the decisions above. As shipped, the key was
`toamaisutaa:userinfo:{scheme}:sub:{subject}` and the entry options carried no
`HybridCacheEntryFlags`, so an application that had registered an `IDistributedCache` for its own
reasons found this package reading its authorization input out of that store, under a key whose only
varying part was the subject: `{scheme}` is `Bearer` for every consumer of `AddToamaisutaaBearer`.

Two services against one issuer sharing an unprefixed Redis is not an exotic deployment - an admin
API and a public API in one org is the ordinary case - and the two hold different scopes, so the
same subject has different claims in each. Whichever fetched first decided for both. That is a
privilege escalation, and neither service asked for it or could see it.

Two changes, both cheap:

- The key carries a SHA-256 of the authority and the accepted audiences (`ValidAudiences`, or
  `ClientId` when that list is empty). Hashed rather than spelled out because an authority is a URL.
  Authority alone would not have been enough: the co-deployed case shares one issuer, and it is the
  audience that tells the two services apart.
- `ShareUserInfoCacheAcrossInstances`, off by default, decides between
  `HybridCacheEntryFlags.None` and `HybridCacheEntryFlags.DisableDistributedCache`. Having a Redis
  registered is not a statement that a package may write claims into it.

The key scoping is the correctness fix and the flag is the one that would still hold if the key were
wrong again, which is why both are here rather than either alone.

`UserInfoCacheTests` now builds its `HybridCache` over a recording `IDistributedCache` for three
tests: nothing reaches it by default, an opted-in second enricher is served from it without calling
userinfo, and two enrichers with different audiences are not. Note for anyone extending them that
`AddDistributedMemoryCache()` does not work here - HybridCache recognises `MemoryDistributedCache`
and declines to use it as an L2 - so the fake is a dictionary behind `IDistributedCache`, which it
does use.
