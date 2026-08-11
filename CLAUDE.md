# Toamaisutaa - working conventions

## Workflow (enforced)

Never work on main. Always:
1. `gh issue create` (with a label)
2. Branch `feature/<issue#>_PascalCase` or `fix/<issue#>_PascalCase`
3. `gh pr create` (with a label) - body is Summary + `Closes #<issue>` only
4. Squash-merge + delete branch

Labels are not decoration here: they drive both the release notes and the version bump. A pull
request merged without one contributes a patch bump and lands in no category.

## Commits

- Past-tense imperative, verb first, one short subject line.
- No AI / Claude attribution. No `Co-Authored-By`, no `🤖 Generated with...`, nothing.

## PRs

- Title mirrors the commit.
- Body: one-line summary + `Closes #<issue>`. No test plans, no checklists, no headers.
- Labels: `feature`, `enhancement`, `bug`, `refactor`, `documentation`, `CI/CD`, `breaking`.

## Writing

- **Never use em dashes.** Not in code, not in comments, not in UI strings, not in docs. Use " - ".
- Comments explain why, not what. If a line needs a comment to say what it does, rename something.

## Personality goes where nothing is being diagnosed

The package has a voice - the katakana, the gate, the README. Keep it away from anything somebody
reads while something is broken.

**Fair game:** the README, the docs site, the sample's demo data and log lines, the release-notes
templates, XML doc remarks.

**Off limits:** exception messages, startup-check failures, the `OnForbidden` diagnostic, and any
log line written when something has gone wrong. Those are read at 2am by someone who needs the
answer in one line, and a joke in front of the answer is strictly worse at the only job they have.
The 403 diagnostic naming which claim was read and what the token actually carried is the single
most useful thing in this package. It stays plain.

The temptation recurs. The rule is the whole defence.

## Layering (enforced)

- `Abstractions` has **zero** package references. Interfaces, options, DTOs, entities.
- `Core` depends only on `Abstractions` and `Microsoft.Extensions.*`. No ASP.NET, no EF - it must
  stay usable from a console app or a worker.
- `AspNetCore` and `OpenIdConnect` use `<FrameworkReference Include="Microsoft.AspNetCore.App" />`,
  never a PackageReference for framework assemblies. JwtBearer is a real package and is referenced
  as one.
- `internal` by default. Every `public` type is a permanent contract - justify each one.

## Versions and packages

- Central package management: versions live in `Directory.Packages.props` as `<PackageVersion>`;
  csproj gets a bare `<PackageReference>` with no `Version`.
- Transitive pinning is **off**. Where a transitive version must be forced, reference it explicitly
  in the project that needs it and say why, so it becomes a real dependency of the package rather
  than a fix for our build alone.
- `<Version>` in `Directory.Build.props` is a **local fallback only**. Releases take their version
  from the git tag. Nothing needs bumping before a release.

## Migrations

Each provider has its own assembly and is its own design-time startup project. Regenerate both
together or they drift:

```
dotnet ef migrations add <Name> \
  --project src/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres \
  --startup-project src/Toamaisutaa.EntityFrameworkCore.Migrations.Postgres \
  --context ToamaisutaaDbContext --output-dir Migrations
```

Instants are stored as Unix milliseconds via `InstantConverters`, not as provider timestamps -
SQLite cannot range-query a `DateTimeOffset`. Use the converter for any new timestamp column.

## Before you claim it works

- `dotnet build Toamaisutaa.slnx` is 0 warnings, 0 errors.
- `dotnet run --project src/Toamaisutaa.Core.Tests/Toamaisutaa.Core.Tests.csproj` is green (TUnit -
  `[Test]`, no `[TestClass]`, the project runs itself).
- If it touches packaging, `dotnet pack` each shipping project and look inside the `.nupkg`.
