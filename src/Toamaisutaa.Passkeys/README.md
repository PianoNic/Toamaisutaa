# Toamaisutaa.Passkeys

Passkeys - WebAuthn - for Toamaisutaa. Opt-in: nothing else references this package, and a
deployment that does not install it has no passkey tables, no passkey endpoints and no FIDO2
dependency.

It is the passwordless half of the library. One prompt proves possession of the authenticator and
verifies the person holding it, which is two factors in a single gesture - so a passkey sign-in
satisfies `TwoFactor:Enforcement` on its own, with no TOTP code on top.

```csharp
builder.Services.AddToamaisutaaPasskeys(builder.Configuration);

app.MapToamaisutaaPasskeyEndpoints();
```

```json
{
  "Passkeys": {
    "RelyingPartyId": "example.com",
    "Origins": [ "https://example.com" ]
  }
}
```

`RelyingPartyId` is the domain a credential is bound to and there is no default, because getting it
wrong is permanent: every credential already registered against the old value is bound to it and
cannot be re-bound.

Six endpoints, under `LocalLogin:EndpointPrefix` + `Passkeys:EndpointPrefix`:

| Method   | Route                          | Who       |
| -------- | ------------------------------ | --------- |
| `POST`   | `/auth/passkeys/register/begin`    | Signed in |
| `POST`   | `/auth/passkeys/register/complete` | Signed in |
| `POST`   | `/auth/passkeys/assertion/begin`   | Anyone    |
| `POST`   | `/auth/passkeys/assertion/complete`| Anyone    |
| `GET`    | `/auth/passkeys`               | Signed in |
| `DELETE` | `/auth/passkeys/{id}`          | Signed in |

Sign-in begins with no identifier at all: the browser finds a discoverable credential itself, so
there is no user name box and nothing to answer whether an account exists.

Full documentation: <https://docs.toamaisutaa.pianonic.ch/passkeys>
