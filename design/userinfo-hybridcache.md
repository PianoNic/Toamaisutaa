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

Nothing to configure. `AddToamaisutaaBearer` calls `AddHybridCache`; an application that has
registered an `IDistributedCache` gets a shared second level from its own registration, and one that
has not gets an in-memory first level and the stampede protection, which is the half that matters
on a cold start.
