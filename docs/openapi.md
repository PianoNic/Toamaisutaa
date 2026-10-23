# OpenAPI

Every endpoint this package maps describes itself: response types, status codes, summaries, and a
tag per group. They appear in a generated document with no work from you.

**The security schemes are one call.** A security scheme is a document-level declaration, so
somebody has to add it: without one, nothing marks which endpoints need a token and Scalar or
Swagger UI shows no Authorize box, which is how most people first try an API.

```sh
dotnet add package Toamaisutaa.OpenApi
```

```csharp
builder.Services.AddToamaisutaaOpenApi(builder.Configuration);   // section "Oidc"

if (app.Environment.IsDevelopment())
    app.MapOpenApi().AllowAnonymous();
```

Anonymous, because an API explorer reads the document before anybody has a token. Development-only
because the document describes every endpoint you have, and publishing it is a decision rather than
a default - map it outside development when you meant to.

That puts four things in the document:

- a **`Bearer`** HTTP scheme, for a token pasted in from `/auth/login` or `/auth/2fa/verify`;
- an **`OAuth2`** authorization-code scheme, with the authorization and token URLs read from your
  issuer's discovery document and the scopes from `Oidc:Scope`;
- the **requirement, document-wide**, naming both schemes as alternatives - either token gets in;
- **no padlock on anonymous endpoints**. `/auth/login` is the endpoint you call because you have no
  token yet.

Its own package, because `Microsoft.AspNetCore.OpenApi` is not part of the shared framework and an
application documenting itself some other way should not pay for it.

If your issuer cannot be reached while the document is generated, the `OAuth2` scheme is left out,
the rest of the document is unchanged, and one warning line says which address failed. With no
`Oidc:Authority` configured at all there is no authorization server to describe, and the `Bearer`
scheme stands alone - which is exactly right for a deployment that only issues its own tokens.

The discovery answer is held for five minutes, so how often this process reaches for your issuer does
not depend on how often the document is read. And where `Oidc:InternalAuthority` is set, an endpoint
the issuer answered with under that address is moved onto `Oidc:Authority` before it reaches the
document: Keycloak with no `KC_HOSTNAME` builds its endpoint URLs from the Host header it was reached
at, and the browser cannot resolve a container name. Endpoints on any other host are left as they
came.

To render it, `Scalar.AspNetCore` is one line:

```csharp
app.MapScalarApiReference().AllowAnonymous();   // /scalar
```

`samples/MinimalApiSample` has both, wired exactly as above.

## With transformers of your own

`AddOpenApi` called twice for the same document registers everything twice, so pass your own
configuration through instead:

```csharp
builder.Services.AddToamaisutaaOpenApi(
    builder.Configuration,
    configureOptions: options => options.AddDocumentTransformer(YourOwnTransformer));
```

Or, where the document is already yours, add the schemes to it:

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddToamaisutaaSecuritySchemes();
    // ... whatever else you already had
});
```
