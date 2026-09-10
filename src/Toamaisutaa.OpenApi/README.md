# Toamaisutaa.OpenApi

The security schemes for a [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) API's OpenAPI
document. One line instead of the thirty-five that used to be pasted into every `Program.cs`.

```bash
dotnet add package Toamaisutaa.OpenApi
```

```csharp
builder.Services.AddToamaisutaaOpenApi(builder.Configuration);   // section "Oidc"

if (app.Environment.IsDevelopment())
    app.MapOpenApi().AllowAnonymous();
```

Anonymous, because an API explorer reads the document before anybody has a token. Development-only
because the document describes every endpoint you have, and publishing it is a decision rather than a
default.

## What it puts in the document

- **A `Bearer` HTTP scheme**, for a token pasted in from `/auth/login` or `/auth/2fa/verify`.
- **An `OAuth2` authorization-code scheme**, whose authorization and token URLs are read from the
  issuer's discovery document and whose scopes are the ones in `Oidc:Scope` - the same string the
  configuration endpoint hands your SPA.
- **The requirement, document-wide**, naming both schemes as alternatives, so either token opens the
  padlock.
- **No padlock on anonymous endpoints.** `/auth/login` is the endpoint you call because you have no
  token yet, and an operation carrying `IAllowAnonymous` gets an empty requirement list.

The URLs are read, never derived. Appending Keycloak's `/protocol/openid-connect/auth` to the
authority is right for one issuer and wrong for the rest, and it fails quietly: the document
generates, the Authorize button appears, and it points somewhere that has never existed.

## Behind an internal authority

Where `Oidc:InternalAuthority` is set, the fetch goes over it - a container reaches its issuer at an
address the browser never sees. What comes back is usually the public URLs, but an issuer that builds
its endpoint URLs from the request's Host header (Keycloak with no `KC_HOSTNAME`) answers the
internal hop with the internal host. An endpoint under the internal authority is therefore moved onto
`Oidc:Authority`, keeping its path, so the Authorize button points where your SPA points. An endpoint
on any other host is left exactly as the issuer gave it.

The answer is held for five minutes, the discovery health check's own interval. The document
transformer runs on every request for `/openapi/v1.json`, and how often this process reaches for the
issuer should not be decided by whoever is reading the document.

## When the issuer cannot be reached

The `OAuth2` scheme is left out and the rest of the document is unchanged, so the `Bearer` scheme
still works. One warning line says which address failed and why. `Oidc:Authority` being unset is not
a failure - it is a deployment that only issues its own tokens, and there is no authorization server
to describe.

A failure is held for the same five minutes as a success, so an issuer that is down costs one
five-second attempt rather than one per reader. The `OAuth2` scheme comes back within that interval
of the issuer coming back.

## Rendering it

Any OpenAPI UI reads the result. [Scalar](https://github.com/scalar/scalar) is one line:

```csharp
app.MapScalarApiReference().AllowAnonymous();   // /scalar
```

## Composing with your own transformers

`AddOpenApi` called twice for the same document registers everything twice, so pass your own
configuration through instead:

```csharp
builder.Services.AddToamaisutaaOpenApi(
    builder.Configuration,
    configureOptions: options => options.AddDocumentTransformer(YourOwnTransformer));
```

Or, if the document is already yours, add the schemes to it:

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddToamaisutaaSecuritySchemes();
    // ... whatever else you already had
});
```

## Documentation

**[Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
