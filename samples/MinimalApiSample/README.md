# MinimalApiSample

A bearer-protected minimal API using Toamaisutaa, with provisioning on SQLite.

## Run it

Start an issuer. This uses [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server), which
is also how the analysed applications run their end-to-end tests - the package ships no
authenticate-everyone handler, on purpose.

```sh
docker run --rm -p 8080:8080 \
  -e JSON_CONFIG_PATH=/config/mock-oauth2-config.json \
  -v "$(pwd)/mock-oauth2-config.json:/config/mock-oauth2-config.json" \
  ghcr.io/navikt/mock-oauth2-server:2.1.10
```

Then:

```sh
dotnet run
```

`MinimalApiSample.http` walks through it: mint a token, call `/api/me`, call `/api/admin`, and see a
401 without a token.

## What each endpoint shows

| Endpoint | Point |
|---|---|
| `GET /api/public` | `AllowAnonymous` opting out of the fallback policy |
| `GET /api/app` | the runtime configuration a SPA reads before sign-in |
| `GET /api/me` | provisioning: the local row is created on the first call and read afterwards |
| `GET /api/admin` | the `Toamaisutaa.Admin` policy from `Oidc:AdminRole` |
| `POST /auth/*` | local password login - see `MinimalApiSample.http` |

Call `/api/me` twice and watch the SQL: the second call reads and writes nothing, because
`ProfileSyncMode` defaults to `OnChange`.

## Local login

`MinimalApiSample.http` walks the whole thing: register, log in, use the token on the same endpoints
an identity provider's token works on, rotate a refresh token, present a rotated one and watch the
family get revoked, change a password, and add a password to an account that arrived through the
identity provider.

Things worth watching in the log rather than the response, because the responses deliberately do not
say:

- `Sign-in refused: no local credential matches` versus `wrong password` versus `locked out`. All
  three answer the same 401 with the same body.
- `Refresh token reuse detected ... revoking the whole family`.
- `Password reset requested for user ..., which has no local credential - an identity provider owns
  it`. That is the case where someone waits for an email that is never coming.

Self-registration is on here because it makes the sample usable. It is off by default in the
package.

## No identity provider at all

The whole point of local login is a deployment that cannot run one. Clear the authority and it still
works:

```sh
Oidc__Authority= dotnet run
```

Register and log in as usual. `/api/me` accepts the locally issued token; a token from the mock
issuer is now rejected, because with no discovery document there are no external keys to trust.

## Pointing it at a real issuer

Change `Oidc:Authority` and `Oidc:ClientId`. Nothing in the package assumes a particular provider;
every endpoint comes from the issuer's discovery document. For Pocket ID, Authentik or Entra, also
set `Oidc:RoleClaim` to `groups`, since those publish membership there rather than in `roles`.

## Switching to Postgres

Reference `Toamaisutaa.EntityFrameworkCore.Migrations.Postgres` instead of the SQLite one and change
the two lines in `Program.cs`:

```csharp
builder.Services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
```
