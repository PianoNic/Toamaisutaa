# Signing local tokens

Local sign-in issues an access token, and something has to be able to check it. By default that is
HS256 from `LocalLogin:SigningKey`: one secret, used to sign and to verify, and nothing more to
manage.

The catch is who can hold that secret. Anything that verifies an HS256 token can also mint one, so a
gateway, a sidecar or a second service cannot be given verification without being given the ability
to impersonate every user. `LocalLogin:SigningKeys` is the answer to that: an asymmetric key, a
public half published at a JWKS endpoint, and a signing half that never leaves this process.

::: tip Which one do you want?
If your API is the only thing that reads these tokens, stay on `SigningKey`. There is no security
gap to close and no keys to rotate. Reach for `SigningKeys` when something else has to validate a
token, or when your platform already expects an issuer to publish a JWKS.
:::

## Configuring keys

```json
{
  "LocalLogin": {
    "SigningKeys": [
      {
        "Kid": "2026-09",
        "Pem": "-----BEGIN PRIVATE KEY-----\nMIGHAgEA...\n-----END PRIVATE KEY-----"
      }
    ]
  }
}
```

Each entry is a key id and the key material as either `Pem` or `Jwk`, one or the other. **The first
entry is the active one**: it signs every token issued from now on, and every entry in the list -
first or not - validates.

RSA and NIST EC keys are accepted, and the algorithm follows from the key rather than being
configured: RSA is `RS256`, and P-256, P-384 and P-521 are `ES256`, `ES384` and `ES512`. RSA keys
below 2048 bits are refused at startup, and so is an EC key on any other curve - `secp256k1` is a
256-bit key that imports exactly like a P-256 one, and the startup message names the curve it found.

A `Jwk` entry may carry its own `kid`, in which case `Kid` can be left out. Generating a key with
OpenSSL:

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt
```

The private key is a credential of exactly the weight of the symmetric one, so it belongs in the
environment or a secret store - never in a settings file you commit. Everything the startup check
knows about the symmetric key it also knows about these: a key that does not parse, a duplicated
`kid` or a first entry that cannot sign refuses the host rather than failing on the first sign-in.
That holds in a process that only validates tokens as well - if you bind `LocalLogin` in a service
that calls `AddToamaisutaaBearer` and nothing else, a key it cannot read still stops the host rather
than turning into a 401 on every token it was configured to accept.

## The JWKS endpoint

```
GET /auth/.well-known/jwks.json
```

Anonymous, under `LocalLogin:EndpointPrefix`, and **only mapped when `SigningKeys` is set**. A
deployment signing HS256 has no public half, and answering an empty set would tell a gateway that
this issuer publishes nothing rather than that it was never asked to.

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "kid": "2026-09",
      "alg": "ES256",
      "crv": "P-256",
      "x": "gJxkTS1yu3nXzO9XL6ZPd5M8uDGNrAZZvqPewwtPM-w",
      "y": "3Rh55kzlvqnhzplLZFntwkl3p-DFPYJ3rja7K5XC_zI"
    }
  ]
}
```

RFC 7517 field names, so anything that already reads an identity provider's JWKS reads this one.
Every configured key is published, not only the active one, because a token signed before a rotation
still has to be checkable. Only public material is ever in there.

Point a gateway at it the way you would at any issuer: the token's `iss` is `LocalLogin:Issuer`, its
`aud` is `LocalLogin:Audience` (or `Oidc:ClientId`), and its `kid` names the key in this document.

## Rotating a key

Put the new key at the front and leave the old one behind it:

```json
"SigningKeys": [
  { "Kid": "2026-09", "Pem": "...the new key..." },
  { "Kid": "2026-03", "Pem": "...the old key..." }
]
```

New tokens are signed by `2026-09` from the next request. Tokens already in flight carry
`kid: 2026-03`, are still validated against that key, and expire on their own within one
`AccessTokenLifetime`. Nobody is signed out.

Once that lifetime has passed, the old entry can be dropped. If you would rather destroy the private
half first, an entry may carry the public key alone - `-----BEGIN PUBLIC KEY-----` - which is enough
to keep validating and not enough to sign. Only the first entry has to be able to sign.

## Moving from HS256

The two shapes coexist so that switching is not an outage. Add `SigningKeys` and **leave
`LocalLogin:SigningKey` where it is**:

- new tokens are signed asymmetrically from the moment the process starts;
- tokens already in flight are HS256, and the symmetric key is still in the validation set, so they
  keep working until they expire.

Remove `SigningKey` on the next deploy, once one `AccessTokenLifetime` has passed. Refresh tokens are
unaffected by any of this - they are database rows, not JWTs, so a key change never invalidates a
session.

## What validates what

The bearer handler validates both a locally issued token and your identity provider's, and the keys
are bound to their issuers rather than pooled:

- a token whose `iss` is `LocalLogin:Issuer` is checked against the local keys, picked by `kid`, and
  never against the identity provider's;
- a token from the identity provider is checked against its keys, and never against the local ones.

That binding is why an identity provider cannot mint a token claiming the local issuer - whose
subject is a local user id - and why a `kid` naming no configured key is refused outright rather than
tried against everything in the set.
