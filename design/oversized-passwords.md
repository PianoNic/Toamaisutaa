# Bounding what reaches the hasher (#398)

Sign-in hashed whatever password arrived, `MaximumPasswordLength` being checked only when a password
was set, and nothing limited how many hashes ran at once. A login body could be Kestrel's 30 MB, and
each request paid a full PBKDF2 or Argon2.

## What changed

- **Length.** Sign-in refuses a password over `MaximumPasswordLength` before looking up the
  identifier, so the answer is the same for a real and an unknown account, and pays the dummy hash on
  the first `MaximumPasswordLength` characters for timing. A current-password check counts a password
  that long as wrong without hashing it. Registration, reset and admin passwords already went through
  the validator.
- **Body.** `LocalLogin:MaxRequestBodyBytes` (256 KiB, room for a passkey's attestation) as
  `IRequestSizeLimitMetadata` on all five endpoint groups. Routing turns it into the request's body
  limit, so Kestrel answers 413 before reading.
- **Concurrency.** One `ConcurrencyLimiter` for the process (twice the processor count, a queue of
  100) in the filter that already guards the password and code endpoints, held for the whole request.
  Past the queue: 503, not 429, because the caller is inside its own budget. Independent of
  `RateLimit:Enabled`, since it protects the server rather than an account.

## The test server does not enforce body limits

The first body test posted 4 KB against a 1 KB limit and got 401: `TestServer` has no
`IHttpMaxRequestBodySizeFeature`, so routing's limit goes nowhere. The HTTP test now asserts what is
the package's own doing, that every `/auth` endpoint carries the configured limit (removing it from one
group reddens it), and the enforcement was checked by hand on Kestrel: the getting-started app from
#397, rebuilt against this branch, answered 413 to a 400 KB login body and 401 to a normal one.

## Verification

Four mutations, each reddening its own test.
