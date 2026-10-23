# Docs trim: rationale moved out of the published site

Issue #366 cut the consumer docs by roughly a third. Design history, upgrade notes and the arguments
behind decisions that a consumer does not need to act on were moved here verbatim, grouped by the page
they came from, so nothing written down is lost. Where the consequence still matters to a consumer,
the page keeps one sentence of it.

## password-login.md

### A new claim and the refresh path

(Maintainer guidance. A two-line consumer version now lives in `customizing-password-login.md`.)

> If you replace `IAccessTokenIssuer` and add a claim, decide in the same change what
> `RefreshAsync` does with it: **recompute it, carry it on the refresh token row, or drop it
> deliberately.** All three are defensible; not having decided is not.
>
> A refresh that silently drops a claim produces a token that is correct at sign-in and wrong exactly
> one `AccessTokenLifetime` later, which reads as a policy failure rather than a refresh failure. This
> package has made that mistake three times and never once caught it with a test.

### Why a first password carries no email, and why a user name is never an address

> The new credential signs in with the user name and carries no email address. The provider's email is
> only what the provider asserted, and copying it in made it a reset address for a mailbox nobody had
> shown the account owns. Add the address through `/auth/email`, which proves it.
>
> The user name is the provider's handle, and never its email. An account whose handle is missing or
> shaped like an address (a UPN is one) gets 400 here: in the user-name column an address becomes a
> hold on it that proving the mailbox cannot release. Such an account can use passkeys or magic links
> instead.

### Why `/auth/password/forgot` sends after the response

> The lookup and the mail happen after the response, on a background
> queue, so a real account takes no longer to answer than an unknown address: waiting on the mail
> server inside the request told the clock what the body would not.

### Why the access token carries only a verified `email`

> `email` is the claim
> an identity provider's token uses too, and everything downstream reads it as proven: a token that
> asserted a typed address let anyone register as somebody else's and pass every policy keyed on it.

### The camelCase / snake_case asymmetry

> The asymmetry is deliberate and it is the one thing here you cannot guess.

## two-factor.md

### No new dependency

> No new dependency. RFC 6238 is a keyed hash, a big-endian counter and a modulo, all of which are in
> the base class library, so there is no TOTP package here and no QR code renderer either - enrolment
> hands you an `otpauth://` URI and your application draws it.

### Why enrolment is two steps

> One step would mean that anyone who opened the settings page, generated a secret and closed the tab
> without scanning anything would be locked out of their own account with no way back in. The
> ceremony exists so that the account is never protected by a secret nobody has proved they hold.

### Breaking change: `/auth/login` gained a second success shape

> ::: warning Breaking change
> Existing clients that assume `/auth/login` returns tokens will break the moment a user enrols. This
> is why it is a status shape rather than a new status code: the branch is explicit and cannot be
> missed by a client that only checks for 200.
> :::

### Why recovery codes are keyed

> A code is ten characters so a person can type it from paper, which is
> about fifty bits: plenty against guessing online, nowhere near enough against a copy of the table.
> Stored as a plain hash, one offline sweep recovered every user's codes; keyed, the table alone is not
> enough to check a guess.

### Why the TOTP key is separate from the signing key

> Use a different key from `LocalLogin:SigningKey`. They do different jobs, they rotate on different
> schedules - rotating a signing key signs people out for fifteen minutes, rotating this one means
> re-encrypting every enrolment - and a signing key can be
> [asymmetric](/token-signing), which an AES key cannot be.

### Step-up `amr` and RFC 8176

> A recovery code adds only `mfa`, matching what a recovery *sign-in* records - RFC 8176 has no
> `recovery` value and this package does not invent claim values.

### `toa_2fa_enrolled` and the earlier `amr=mfa`

> An earlier version wrote `amr=mfa` for any
> enrolled user, which let a phished provider password pass the second-factor policy.

### Why the stamp is not checked on every request

> It is deliberately not compared on every bearer request, which would cost a read
> per request forever.

### Never log the enrolment response (full section)

> `/auth/2fa/begin` returns the secret in plaintext - as base32, and again inside the URI. It has to;
> an authenticator cannot be enrolled without it. That makes it the one response in this package that
> is itself a long-lived credential.
>
> Do not log it. Not the value, not the URI, not a truncated prefix, not at Debug. A log line added
> while chasing a bug ships to wherever your logs aggregate, outlives every key rotation anyone will
> remember to perform, and cannot be recalled - and putting it right means every affected user
> enrolling again. The same goes for recovery codes.
>
> Nothing in this package logs either one. Log the user id and what happened.
>
> #### The leak is easiest to add by accident in your own pipeline
>
> Nothing here logs the secret, but this package cannot stop what wraps it, and one pattern gets it
> wrong reliably: **a mediator or middleware that logs every request and response generically.**
>
> `TwoFactorEnrolmentStarted` carries `Secret` and carries it again inside `Uri`. Put it in a response
> DTO of your own - which is the natural thing to do when you are composing this package's data with
> your own fields - and a pipeline behaviour that serialises responses will write a live TOTP secret
> to your logs without anyone writing a line of code that mentions it.
>
> `TwoFactorEnrolmentCompleted.RecoveryCodes` is the same class of thing.
>
> If you have that kind of behaviour, exclude these two types from it explicitly, and do it before you
> wrap them rather than after you find them in a log search.

### Why `Digits` and `Period` are configurable at all

> `Digits` and `Period` are configurable and documented as "do not change these" - anything other than
> 6 and 30 breaks Google Authenticator. They exist so that somebody with an unusual authenticator does
> not have to fork the package, not because anyone should touch them.

### The `MoveSecurityStampToUser` migration

> The `MoveSecurityStampToUser` migration ships alongside it and moves `SecurityStamp` from
> `ToamaisutaaPasswordCredentials` onto `ToamaisutaaUsers`, copying existing values across. A second
> factor belongs to the person, not to one way of proving they are them, and a user provisioned by an
> identity provider has no credential row to hang it off.

## spa.md

### The sign-in branch, as it was written on the SPA page

> ::: danger Read this one even if you skim the rest
> `POST /auth/login` returns **200 with tokens** or **200 with a challenge and no tokens**. Same status
> code, different bodies, and the second one does not exist until a user enrols in two-factor - after
> which it exists forever.
>
> A client that checks `response.ok` and reads `access_token` works perfectly until the first person
> turns on 2FA, then breaks for that person only, in production, long after this code was written.
> **Branch on `two_factor_required`.**
> :::
>
> This is the branch clients get wrong, because it does not exist until somebody enrols in two-factor
> and then it exists forever.
>
> Both shapes are 200. A client that checks `response.ok` and reads `access_token` gets `undefined`
> the first time any user turns on two-factor, which is a bug that ships long after the code was
> written.

### Why access tokens cannot be revoked

> There is no way to revoke one, by design - checking a revocation
> list on every request is a database read this package will not add.

## trusted-devices.md

### Why `toa_sid` is namespaced

> `toa_sid` is an identifier, not a credential: nothing authorises on it, and the bearer token
> carrying it was already the thing worth protecting. It is namespaced rather than the registered
> `sid` because an identity provider may put its own `sid` on an external token, and two issuers
> writing one claim to mean two different sessions is a collision nothing downstream could untangle.

## sessions.md

### A session established before you upgraded

> ::: warning A session established before you upgraded
> The three columns are new. Rows that already existed have no user agent, no address, and a
> `lastUsedAt` of the Unix epoch until their next refresh writes a fresh row. Nothing breaks; an old
> session simply looks blank in the list for a while.
> :::

### Why a separate `IpAddressStorage` setting

> Its own setting rather than the trusted-device one it mirrors, so that an address you asked to store
> against a session does not depend on whether you switched trusted devices on.

### A custom store

> `IRefreshTokenStore` gained `ListActiveAsync`, which returns the live row of every family a user has:
> not rotated, not revoked. There is no default implementation, deliberately - one that returned
> nothing would show an empty session list while the sessions were live, and answer 404 to every
> attempt to revoke one. A compile error is the cheaper failure.

### Why expired sessions are not listed

> They are refused at the next refresh rather than
> swept off a timer, so the row is still there - but offering somebody a session that is over, and a
> revoke button that changes nothing anyone can observe, is worse than leaving it out.

## magic-link.md

### Why the verified-address rule is not an option

> The reason is the difference between this and a reset link. A reset link mailed to a typo'd address,
> or to one somebody else now owns, lets whoever reads it set a password - which is bad, and which is
> why `RequireVerifiedEmailForPasswordReset` exists as a choice. A magic link mailed to the same
> address *is the account*, immediately, with nothing else asked for. There is no version of that worth
> offering as a setting.

### `amr=email` and RFC 8176

> `email` is not one of the RFC 8176 values; the registry has nothing for possession of a mailbox. It
> is spelled the way identity providers offering emailed sign-in already spell it, and left unprefixed
> for that reason, unlike the `toa_` claims this package invents.

### Why the link is spent on the way to the challenge

> It got
> the account holder as far as the second factor, which is all a first factor ever does - and the
> alternative leaves a live credential sitting in a mailbox that has already been read once.

### The lifetime that was argued down

> Fifteen minutes is the one lifetime in this package that was argued *down*. A reset link is a step
> towards a session and can afford an hour; this one is the session, so the window in which a
> forwarded or archived message still works is kept short.

## passkeys.md

### Why the challenge row keeps the options

> The challenge row holds the WebAuthn options exactly as they went to the browser. They carry the
> challenge, the relying party and the user verification requirement, and every one of those is a rule
> the completion step measures the authenticator against - so they are kept here rather than handed to
> the client to give back, which would let it mark its own work.

### Why a failed assertion spends the challenge

> A mistyped six-digit code deserves a second try; an authenticator response is produced by software in
> one shot, so a failed one is not a typo.

### Why a password reset deletes passkeys

> It is the same list
> the sessions and the trusted devices are on, and for the same reason - somebody doing any of those
> is reacting to another person having had access, and a credential that signs in with no password at
> all would outlive the one remediation the package offers.
>
> Re-registering is one prompt on the device that still holds the
> credential, and the alternative is a reset that ends every session while leaving whatever somebody
> else registered exactly where it was.

## storage.md

### Breaking changes to `IUserStore`

> ::: warning Breaking: `IUserStore` gained `SetUserNameAsync`
> [Completing a reserved invitation](/provisioning-accounts#completing-a-reserved-invitation) sets a
> user name on a row that was created with only an email, and no existing method could write it. A
> custom `IUserStore` needs the new member before it compiles against this version.
> :::
>
> ::: warning Breaking: `IUserStore` gained `SetEmailAsync`
> [Email verification](/email-verification) writes the proven address onto the credential, and the
> profile field the notifiers address their mail to has to follow it. A custom `IUserStore` needs the
> new member before it compiles against this version.
> :::

### Why not Pomelo

> That is not a
> judgement about either: Pomelo has no EF Core 10 release, and its latest version pins
> `Microsoft.EntityFrameworkCore.Relational` to `[9.0.0, 9.0.999]`, so it cannot coexist with the rest
> of this package. If Pomelo ships for EF Core 10 and you would rather use it, the swap is a provider
> package and a regenerated migration - nothing in the schema changes.

### The case-insensitive subject bug

> The default collations on SQL Server and MySQL ignore
> case, and MySQL's ignores accents as well, so the unique index on `(ProviderKey, Subject)` treated
> `alice` and `ALICE` as one subject and the second could never be provisioned.
>
> The shipped migrations give the column a binary collation on those two - `Latin1_General_100_BIN2`
> and `utf8mb4_bin` - and existing rows keep their values.

### Why credentials are not columns on the user

> If that same column were the unique local-login identifier, an administrator
> editing an email in your directory would silently change what someone types into your login form -
> and a collision would throw out of an unrelated request. A login identifier and a profile field have
> different rules.

### Why timestamps are integers

> SQLite has no timestamp type, so EF keeps a `DateTimeOffset` as text and then declines to
> translate `<` or `>` on it - correctly, since values written with different offsets do not sort right
> as strings. An integer sorts identically on both providers and can be range-queried on both.
>
> Both are right for audit timestamps, and both are visible enough that someone will notice.

## password-hashing.md

### Why not just SHA-256?

> It is SHA-256. PBKDF2-HMAC-SHA256 is SHA-256 run 600,000 times in a chain, where each round's output
> feeds the next, so there is no way to skip to the end.
>
> That chain is the entire feature. A single SHA-256 is built to be fast, and fast is the wrong
> property for a password: commodity hardware does billions of SHA-256 operations a second, so a
> stolen table of single-round hashes is a dictionary attack that finishes over lunch. Six hundred
> thousand rounds makes one guess cost about a tenth of a second. Nobody notices that once at sign-in;
> an attacker working through a word list notices it every single time.
>
> The salt handles the other half. Without one, identical passwords produce identical hashes, so
> cracking one row cracks every account that shares that password and a precomputed table works
> against everybody at once. With one, each row has to be attacked on its own.
>
> #### The rule underneath
>
> This codebase uses both. Passwords go through 600,000 rounds of PBKDF2 with a salt; refresh tokens,
> password reset tokens and recovery codes are stored as a **plain, unsalted, single-round SHA-256**.
> That is not an inconsistency, and the deciding question is always the same one:
>
> **Does the input have entropy of its own?**
>
> - **Passwords do not.** People choose them, from a space small enough to enumerate. The hash has to
>   supply the cost that the input does not, which is what iteration buys - and a salt, because
>   low-entropy inputs collide across users.
> - **Tokens do.** They are 256 bits straight from the system random generator. There is no dictionary
>   to try, so iteration defends against nothing; no two can collide, so a salt has nothing to do. All
>   that is left is looking one up by exact match on every request, which a fast hash does well and a
>   slow one would turn into a per-request cost buying nothing.
>
> So: slow and salted when a human picked it, fast and plain when the random generator did. Reach for
> the expensive one by default, and be able to say why when you do not.

(Note: recovery codes have since moved to a keyed HMAC - see `two-factor.md`. The essay above
predates that.)

### Why Argon2 is not the default

> It is not the default here for a dependency reason rather than a cryptographic one. PBKDF2 is in the
> base class library; .NET has no in-box Argon2, and none is coming, because the runtime delegates
> primitives to the platform and only OpenSSL implements it. Taking a third-party package into the
> credential path of a library other people install is a decision this package will not make on your
> behalf.
>
> So it is your decision, in one line.

## breached-passwords.md

### Why a refused-by-length password is never looked up

> There is nothing to learn about a
> password nobody is going to end up with, and asking would spend a request on every short password
> typed into an anonymous endpoint.

### SHA-1

> SHA-1 is not a security choice here. It is the index the corpus is published under, and nothing
> about a password is recoverable from five hex characters of it.

### Why it fails open

> That is a deliberate trade. This is a second opinion on a password the length rules already
> accepted, and a third party being down must not be the reason nobody in your deployment can
> register or change their password.

## oidc.md

### Userinfo request coalescing, before `HybridCache`

> A page reload
> against a cold cache fires a dozen requests before any of them has answered, and that used to be
> a dozen calls to your issuer.

### Why sharing the userinfo cache is opt-in

> It is a switch rather than the default because of what these entries are. They decide authorization,
> and they carry whatever else your issuer puts in userinfo, which is usually an email and a name. On
> the way in, they become a plaintext value in a store the package does not own, next to every other
> tenant of it. Deciding that is fine is a reasonable thing to do, and it is not something the package
> can decide on your behalf from the presence of a Redis connection string.

### Health check internals

> Degraded rather than unhealthy for a recent fetch is the point of the distinction. A handler that
> loaded the document keeps validating tokens against the keys it already holds, so taking the
> instance out of rotation would break something that still works - but you want to know before the
> issuer rotates its signing keys.
>
> That answer is bounded, because degraded is a 200 and a 200 keeps the instance in the load balancer.
> `Oidc:HealthCheck:DegradedFor` is how long the last successful fetch counts for; past it the check
> reports unhealthy, on the grounds that an issuer nobody here has reached for a quarter of an hour is
> no longer evidence of anything.
>
> What the check reports is what the check itself fetched. It has its own client and its own refresh
> interval, and cannot see the document the bearer handler holds - that one lives in the handler's
> `ConfigurationManager` and is loaded lazily on the first request carrying a token, so a process that
> has only served anonymous traffic has none at all.
>
> A 200 that is not a discovery document counts as a failure. A reverse proxy that has lost its route
> answers a sign-in page with one, and the handler needs the keys rather than the status.
>
> A successful fetch is trusted for `Oidc:HealthCheck:RefreshInterval`, and probes in between are
> answered from it. Readiness probes run every few seconds across every replica, and fetching on each
> one would put a steady load on the issuer for an answer that changes rarely. A failed fetch is
> remembered for the same interval, and probes that arrive together share one request, so an issuer
> that is struggling is not also handed a fetch per probe - the health endpoint is usually anonymous.

### Why inbound claim mapping is off

> .NET's
> default remaps claims to WS-Federation URIs, which leaves `Oidc:NameClaim` and `Oidc:RoleClaim`
> naming raw JWT claims that no longer exist on the principal - a `NameClaimType` that quietly matches
> nothing. Turning it off everywhere means one set of names, the issuer's.

## Further rationale trimmed in the same pass

### two-factor.md: step-up

> Rotating the family here would mean a client that ignored a new refresh token
> presented a spent one at its next refresh, tripping reuse detection - so proving your identity would
> end every session you have.

> Somebody holding a stolen access token can lock the owner
> out of step-up, and that is the right trade - the alternative is handing that same person an
> unthrottled six-digit oracle.

### passkeys.md

> A
> passkey signs in with no password and no code, so adding one is adding a way into the account, which
> puts it alongside disabling the second factor rather than alongside reading a list.

> `/register/complete` asks for nothing further, because the challenge it redeems
> was only issued against a proof that held.

> The passkey would otherwise be a way in that skips the code.

> Standard base64 and padding either way are
> accepted too, because the encoding happens in whatever your client is written in and they do not
> agree.

> so the endpoint has nothing that could answer whether an account
> exists

> An authenticator that
> cannot store one is refused at registration rather than at the sign-in where it would silently fail
> to appear.

> so a user whose only second factor is their phone is
> not told to go and set up an authenticator app as well.

> Somebody who turned a second factor on is
> asked for it, and one borrowed security key with no PIN is not the way around it.

> Unlike registering, the
> password alone is enough even on an account with a second factor, since removing a way in adds
> none. A bearer token alone could otherwise delete every passkey on an account that has no password.

> Nothing records which
> session a given key opened, and a key is removed when somebody suspects it is not only in their hands,
> so none of them is left to outlive it.

### trusted-devices.md

> **Putting it in `localStorage` means any XSS gets a permanent second-factor bypass.** Not a session,
> not a stolen access token that expires in fifteen minutes - a token that skips 2FA for thirty days,
> readable by any script that runs on your origin. That is the consequence; the choice is yours.

> A device signed in from every single day still has to complete a live challenge after thirty
> days, which is the difference between an expiry and a suggestion.

> Every live device is a
> second factor somebody is not being asked for, and without a cap they accumulate one per browser.

### spa.md

> - **Two tabs signing in at once will lose the device.** Both present the same token, the second
>   looks like a replay, and the family is revoked. Refresh tokens behave the same way and it is the
>   right trade, but it is a real thing that happens.

> Not every 403 is worth a prompt: for a page the user simply cannot reach, showing the wall is
> kinder than asking for a code and then showing it anyway.

### storage.md

> `OnChange` exists because the obvious implementation - refresh the row on every authenticated
> request - costs a write per request forever.

### provisioning-accounts.md

> Nothing you install for
> authentication implements any of them - sending mail, or generating a credentials sheet, is not an
> authentication library's job. The opt-in `Toamaisutaa.Email.Smtp` package is the exception, and it
> is a separate package for exactly that reason.

> the same rule `/auth/register`
> follows for `AllowSelfRegistration`, and a 404 rather than a route behind a policy that was never
> registered. [...] because the endpoints simply not being there is otherwise hard to tell from a typo in
> the path.

> Two calls rather than one, because the second is what puts the two endpoints on the wire, and an
> application that installed the package to send reset mail did not ask for them.

> the account is locked down whether or not the mail went out, because that is the half an admin
> reset exists for.

> the same way the reset link template is handled, and for
> the same reason: the shipped template cannot invent a page it knows nothing about.

### email-verification.md

> it also retires any outstanding verification link, because a pending change of address
> is a credential in flight and a password change is the moment somebody is most likely reacting to a
> break-in.

### token-signing.md

> A
> deployment signing HS256 has no public half, and answering an empty set would tell a gateway that
> this issuer publishes nothing rather than that it was never asked to.

> The private key is a credential of exactly the weight of the symmetric one

### oidc.md

> A wrong `Oidc:Authority` or an unreachable `Oidc:InternalAuthority` is invisible until the first
> request carrying a token, and then it is a 401 - which reads as "my login is broken" rather than "the
> issuer was never reachable from this container".

> there is no separate switch, so "enabled but
> scoped to nothing" cannot happen.

### audit-events.md

> Auditing that turns a correct sign-in into a 500 is worse than no auditing. [...] a sink that throws
> from its constructor, which is why sinks are built when the first
> event of a request is published rather than when the services around them are resolved.

> an audit table usually outlives every key rotation anyone remembers to perform.

### metrics.md

> A time series outlives a log line by a long way and gets shared with whoever is on call, so the
> dimensions here are all small fixed sets. Which account something happened to is in the logs, where
> it can be aged out.

> or your attempt rate would climb with session length rather than
> with traffic.

### password-login.md: the IPv6 site limit

> since a
> /48 is free to get and would otherwise be 65,536 separate budgets.
