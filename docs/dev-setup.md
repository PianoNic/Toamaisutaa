# Developer setup

Prerequisites: **.NET 10 SDK**, and **Docker** if you want to run the sample against an identity
provider.

```sh
git clone https://github.com/PianoNic/Toamaisutaa
cd Toamaisutaa
dotnet build Toamaisutaa.slnx
```

## Tests

TUnit, not xUnit - the test project is an executable and runs itself:

```sh
dotnet run --project src/Toamaisutaa.Core.Tests/Toamaisutaa.Core.Tests.csproj
```

The suite covers the parts with real branching: claims mapping and the display-name fallback chain,
the provisioning and linking decision matrix, userinfo JSON flattening, password hashing including
pepper rotation, lockout arithmetic, refresh rotation and reuse detection, and reset-token
lifecycle.

## Running the sample

`samples/MinimalApiSample` runs the whole thing against
[mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) - which is also how the
end-to-end checks run, because the package deliberately ships no authenticate-everyone handler.

```sh
cd samples/MinimalApiSample

docker run --rm -p 8080:8080 \
  -e JSON_CONFIG_PATH=/config/mock-oauth2-config.json \
  -v "$(pwd)/mock-oauth2-config.json:/config/mock-oauth2-config.json" \
  ghcr.io/navikt/mock-oauth2-server:2.1.10

dotnet run
```

`MinimalApiSample.http` walks through it: mint a token, call the protected endpoints, register a
local account, rotate a refresh token, and watch a reused one revoke its whole family.

To prove the local-login-only path, clear the authority and everything still works:

```sh
Oidc__Authority= dotnet run
```

## Migrations

Each provider has its own assembly, and each is its own design-time startup project:

```sh
dotnet ef migrations add YourMigration \
  --project src/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres \
  --startup-project src/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres \
  --context ToamaisutaaDbContext --output-dir Migrations
```

Then the same for `.Sqlite`. Both must be regenerated together, or the two providers drift.

## Documentation

This site is VitePress, self-contained in `docs/`:

```sh
cd docs
bun install
bun run dev
```

## Releasing

Release Drafter keeps a draft up to date on every push to `main`, named from the labels on the
merged pull requests. Publishing that draft creates the tag and runs `release.yml`, which packs
every package at the tag's version, pushes to nuget.org with Trusted Publishing, and attaches the
`.nupkg` files to the release.

Nothing in the repository has to be bumped first - the tag is the only source of the version. The
guard refuses to publish a version already on nuget.org, one that goes backwards, or a 1.x version
while the library is pre-1.0.

## Conventions

Every change goes: issue, branch (`feature/<issue#>_PascalCase` or `fix/<issue#>_PascalCase`), pull
request with a label, squash-merge. Commit subjects are past-tense imperative, verb first. Labels
matter beyond tidiness - they drive both the release notes and the version bump.
