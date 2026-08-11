# Toamaisutaa.OpenIdConnect

Bearer token validation for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa). This is the
resource-server half: it validates the tokens your identity provider issues, and signs the ones
local password login issues, so that nothing downstream can tell the two apart.

```csharp
builder.Services.AddToamaisutaaBearer(builder.Configuration);   // section "Oidc"

app.UseAuthentication();
```

```json
{
  "Oidc": {
    "Authority": "https://id.example.com/realms/main",
    "ClientId": "your-api",
    "RoleClaim": "roles"
  }
}
```

Every endpoint comes from the issuer's discovery document, so Keycloak, Authentik, Pocket ID, Okta
and Entra are a configuration change rather than a code change.

## What it does beyond the defaults

- **`MapInboundClaims` is off**, always. Claims keep the names the issuer gave them, so `sub` is
  `sub` and not a SOAP-era URI that only matches by accident.
- **Userinfo enrichment**, for issuers that keep group membership out of the access token entirely.
  Off unless configured.
- **403s that explain themselves.** Every refusal logs which claim was read, what the token actually
  carried there, and every claim type present. An empty 403 with a valid token is a miserable
  afternoon; this is the fix.
- **Query-string tokens for named paths**, because SignalR's browser transport cannot set a header.
  Opt-in per path prefix rather than globally.

This package does not perform an interactive login. It is a resource server: the browser gets its
tokens from the identity provider, and this validates them.

Pair it with `Toamaisutaa.AspNetCore` for authorization policies, `ICurrentUser` and the endpoints.

## Documentation

**[OIDC bearer validation](https://docs.toamaisutaa.pianonic.ch/oidc)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
