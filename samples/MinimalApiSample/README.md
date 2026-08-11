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

Call `/api/me` twice and watch the SQL: the second call reads and writes nothing, because
`ProfileSyncMode` defaults to `OnChange`.

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
