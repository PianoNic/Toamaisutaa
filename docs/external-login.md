# Sign in with another provider

"Sign in with Google", Microsoft, Authentik, Pocket ID, Keycloak, or any issuer with a discovery
document, offered next to the password box. The provider says who somebody is; your application
decides which account that is and signs them in with **its own** tokens, exactly as a password
would. Sessions, refresh, revocation, trusted devices and two-factor all behave as they do for
password sign-in.

This is not [OIDC bearer validation](/oidc), which accepts a provider's tokens as they are. Use
that when the provider owns sign-in; use this when your application does and providers are one way
in among several.

```csharp
builder.Services.AddToamaisutaaExternalLogin(builder.Configuration);   // section "ExternalLogin"
builder.Services.AddToamaisutaaTokenCleanup();                         // required, see below

app.MapToamaisutaaExternalLoginEndpoints();
```

Needs local password login registered, because a provider sign-in ends in the same token pair a
password sign-in does and that is where the issuer lives. With no providers configured nothing is
mapped, so a hoster who wants no single sign-on leaves the section out.

## Configuration

```json
{
  "ExternalLogin": {
    "Providers": {
      "google": {
        "DisplayName": "Google",
        "Authority": "https://accounts.google.com",
        "ClientId": "1234-abc.apps.googleusercontent.com",
        "ClientSecret": "from-the-google-console",
        "AllowSignUp": true
      },
      "authentik": {
        "DisplayName": "School account",
        "Authority": "https://auth.example.com/application/o/myapp/",
        "ClientId": "myapp"
      }
    },
    "AllowedReturnUrls": [ "https://app.example.com/auth/callback", "myapp://auth/callback" ]
  }
}
```

Register this address with each provider as the redirect URI:

```
https://api.example.com/auth/external/{key}/callback
```

| Provider setting | Default | |
|---|---|---|
| `DisplayName` | the key | What the button says |
| `IconUrl` | none | Passed to clients as is |
| `Authority` | none | The issuer. Its `/.well-known/openid-configuration` names everything else. `https://` outside Development |
| `ClientId` | none | The id the provider issued |
| `ClientSecret` | none | Sent to the token endpoint when set. Leave it out for a public client; PKCE is used either way |
| `Scopes` | `openid profile email` | Must include `openid` |
| `AllowSignUp` | `false` | Whether a stranger can create an account by signing in here |
| `LinkByVerifiedEmail` | `false` | Whether a first sign-in joins the account that already holds its address. See below |
| `TrustEmailVerified` | `false` | Whether an address this provider verified goes in the token as `email`. See below |

| Setting | Default | |
|---|---|---|
| `AllowedReturnUrls` | none | Where a finished sign-in may send the browser. Matched exactly, the whole string |
| `CallbackBaseUrl` | the request's | The scheme and host the callback is reached on. Set it behind a proxy that does not forward the original host |
| `RequestLifetime` | 10 minutes | How long the user has at the provider |
| `ExchangeCodeLifetime` | 2 minutes | How long the code handed back can be exchanged |
| `LinkProofWindow` | 5 minutes | How fresh a sign-in an account with no password and no second factor needs to link or unlink |
| `EndpointPrefix` | `/external` | Composed onto `LocalLogin:EndpointPrefix` |

The key is permanent in the way a database column name is: it is what the stored link says, so
renaming `google` to `gmail` leaves every linked account pointing at a provider that no longer
exists.

::: tip Microsoft
`https://login.microsoftonline.com/common/v2.0` works: its discovery document publishes an issuer
template rather than an issuer, and each token is checked against its own tenant. Use your tenant id
instead of `common` to accept only your organisation.
:::

## The endpoints

| Method | Route | Who |
|---|---|---|
| `GET` | `/auth/providers` | Anyone. Key, display name and icon per provider |
| `GET` | `/auth/external/{key}/start` | Anyone. Navigate here; it redirects to the provider |
| `GET` | `/auth/external/{key}/callback` | The provider, via the browser |
| `POST` | `/auth/external/exchange` | Anyone holding a code and its verifier |
| `POST` | `/auth/external/{key}/link` | Signed in. Starts linking a provider |
| `GET` | `/auth/external/logins` | Signed in. The linked providers |
| `DELETE` | `/auth/external/logins/{key}` | Signed in. Unlinks one |

## Signing in, from any client

One flow for a SPA and a native app alike. The client makes a PKCE pair of its own, so the code
that comes back is worthless to anyone who reads it off a redirect without the verifier.

```js
// 1. A random verifier, kept until step 3, and its S256 challenge.
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
sessionStorage.setItem('pkce', verifier)

// 2. Navigate, do not fetch.
location.href = `/auth/external/google/start?returnUrl=${encodeURIComponent('https://app.example.com/auth/callback')}`
  + `&codeChallenge=${challenge}&codeChallengeMethod=S256&state=${someState}`

// 3. On https://app.example.com/auth/callback?code=...&state=...
const params = new URLSearchParams(location.search)
if (params.has('error')) return showError(params.get('error'))

const response = await fetch('/auth/external/exchange', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ code: params.get('code'), codeVerifier: sessionStorage.getItem('pkce') }),
})
```

The exchange answers exactly what `/auth/login` does: tokens, or a
[second-factor challenge](/password-login#bodies) to finish at `/auth/2fa/verify`. Branch on
`two_factor_required` the same way. The code is spent by the first attempt, right verifier or
wrong, and expires after two minutes.

A native app does the same with its own scheme in `AllowedReturnUrls` - `myapp://auth/callback` -
opening `/start` in the system browser (`ASWebAuthenticationSession`, Custom Tabs) rather than a
web view, and catching the redirect back.

What can come back on the return URL instead of `code`:

| `error` | Meaning |
|---|---|
| `access_denied` | The user said no at the provider |
| `account_not_found` | Nobody is linked to that identity and `AllowSignUp` is off |
| `account_exists` | Somebody here already holds the address the provider gave. Sign in another way and link the provider from settings |
| `external_login_failed` | Anything else. The log line says what |

`state`, if you sent one, comes back untouched on every answer.

## What the tokens say

`amr` is `["fed"]`, or `["fed", "otp", "mfa"]` after a second factor here. Nothing the provider said
about how it authenticated the user is carried over, its own `amr` and `acr` included: a provider
claiming `mfa` does not satisfy `TwoFactor:Enforcement`, because nothing here checked it. An account
with a confirmed second factor is asked for it after every provider sign-in, as after a password,
and a trusted device does not skip it.

The profile is written once, when an account is created by a first sign-in. Later sign-ins do not
copy the provider's name or address over an account's own.

`email` is in a token only for a verified address. An account created by a provider sign-in has no
address verified here, so by default its tokens carry none. Turn on `TrustEmailVerified` for a
provider and the address it last marked `email_verified` counts, for an account without a verified
address of its own. It is checked at every sign-in through that provider and read at every token,
refresh included, so an address the provider stops vouching for, or a provider you stop trusting,
drops out at the next refresh. The same caution as for linking applies: anything your application
grants by address, an administrator list included, it grants to whoever that provider lets claim it.

## Linking and the address problem

The tempting rule is "same address, same person". It is how accounts get taken over: a provider
that lets users type any address and asserts it, or one that asserts addresses it never verified,
hands over every account here whose address its users can name.

So by default a first sign-in whose address an account already holds is refused with
`account_exists`, and the owner links the provider themselves:

```js
const { authorization_url } = await (await fetch('/auth/external/google/link', {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
  body: JSON.stringify({ returnUrl: 'https://app.example.com/settings', currentPassword }),
})).json()

location.href = authorization_url   // comes back with ?linked=google, or ?error=...
```

Linking adds a way into the account, so a bearer token alone is not enough. It takes the same proof
passkey registration does: `code` from the authenticator where the account has a second factor,
`currentPassword` where it has a password, and otherwise a sign-in within `LinkProofWindow`.

`LinkByVerifiedEmail` turns the automatic join on per provider, and then only for an address the
provider marks `email_verified`. Turn it on for a provider that really verifies addresses - Google,
Microsoft work accounts, your own Authentik - and never for one that does not.

Unlinking takes the same proof, ends **every** session on the account, and is refused for the last
way in: an account with no password, no passkey and one linked provider keeps it.

## Required: token cleanup

Every anonymous `/start` writes a row, so without the sweep the table grows as fast as anyone cares
to call it. Startup refuses without `AddToamaisutaaTokenCleanup()`.

## Not the same identity as bearer validation

A link here is stored under the provider's key - `google`. One made by [bearer
validation](/oidc) is stored under `Oidc:ProviderKey`, `Bearer` by default. Pointing both at the same
issuer gives the same person two accounts. Pick one per issuer.
