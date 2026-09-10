# Asymmetric signing and the JWKS endpoint

Issue #74. `design/phase3-api-surface.md` named this as a later phase and deliberately did not guess
at its shape. This is what it turned into, and the three decisions that were not obvious.

## Where the key parsing lives

`Toamaisutaa.Core` may not reference `Microsoft.IdentityModel.Tokens` - the layering rule holds it to
`Abstractions` and `Microsoft.Extensions.*` - and `PasswordLoginStartupCheck` lives in Core. So
either the startup check stops answering for the signing key, or the parsing is done with the BCL.

It is done with the BCL. `LocalSigningKeyRing` reads PEM and JWK entries into `RSA` and `ECDsa`
using `System.Security.Cryptography` alone, and `LocalTokenKeys` in `Toamaisutaa.OpenIdConnect`
wraps those into `RsaSecurityKey` and `ECDsaSecurityKey`. One parser, one answer, and a bad key is
still one line in the same startup message as a bad pepper rather than a separate failure in a
different layer.

It also means the published JWK is built by hand from `ExportParameters(includePrivateParameters:
false)` rather than by `JsonWebKeyConverter`. That was going to be the deciding argument either way:
this document is served anonymously to anything that asks, and building it from an export that
cannot contain a private component is a stronger guarantee than reading the converter's output
carefully once.

## `TryAllIssuerSigningKeys = false`

This is the one that will look arbitrary in a diff.

The key resolver has bound each issuer to its own key since phase 3, and the reason given there was
that a flat key collection lets a token claiming the local issuer validate against the identity
provider's key. With a single local key that resolver could only ever answer with that key, so it
never had to say "none of mine".

With a list it does, and an empty answer from `IssuerSigningKeyResolver` is not treated as a
refusal: the validator reads it as "did not resolve" and falls back to trying every configured key.
The first version of `Refuses_a_token_whose_key_id_names_no_configured_key` caught this on its first
run - a token signed by the configured key under a `kid` naming nothing was accepted, because the
fallback put that key back in front of it.

`TryAllIssuerSigningKeys = false` makes the resolver authoritative. Nothing the identity provider
path relied on is lost, because the non-local branch hands back every key that is not ours rather
than filtering by `kid` - the fallback was doing nothing for it that the resolver does not already
do.

## The JWKS endpoint is not mapped under HS256

Same reasoning as `AllowSelfRegistration` and the admin endpoints: not mapped rather than mapped and
answering something useless. An empty `{"keys": []}` is a 200, and a gateway that fetches it will
then refuse every token it sees with nothing in that pair saying the deployment signs symmetrically.
A 404 on the well-known path is the answer that can be read.

## The bug this turned up

`ExternalLoginProvisioner.TryGetLocallyIssuedUserId` decided whether local login was configured at
all by reading `LocalLogin:SigningKey`, and returned false when it was blank. A deployment that
finishes migrating drops that option, at which point every locally issued token fell through to the
external-login path and was provisioned as a never-seen subject - a new user row per request, on the
happy path, with no error anywhere.

Found by running the sample against the asymmetric configuration, not by a test, which is the third
time that has been how one of these surfaced. `An_asymmetrically_signed_token_resolves_to_the_user_it_names`
covers it now, and reverting the fix reddens it and one other.

## What was considered and left out

- **A `Cache-Control` header on the JWKS route.** Every JWKS client already caches - IdentityModel's
  `ConfigurationManager` for twelve hours by default - and picking a number here would have been
  guessing at somebody else's refresh policy.
- **`application/jwk-set+json` as the content type.** RFC 7517 registers it; Google, Auth0 and
  Keycloak all serve `application/json` anyway, and a client that insists on the registered type
  would already be broken against every issuer people actually run.
- **A discovery document.** `/.well-known/openid-configuration` is a much larger promise than a key
  set - it implies authorization and token endpoints this package does not have. A gateway needs the
  `iss`, the `aud` and the JWKS URL, and those are three lines of its own configuration.
