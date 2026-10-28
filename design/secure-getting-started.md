# A quick start that is safe to copy (#397)

Followed exactly, the quick start opened self-registration to everyone, handing any stranger an
access token for every endpoint that only asks for a signed-in user (and a 409 telling them who has
an account), and printed live reset tokens to stdout, where anyone with the container's logs could
take over accounts.

## What changed

- `AllowSelfRegistration` moves to `appsettings.Development.json`, so a copy run anywhere else has it off.
- The console mailer refuses to start outside Development, with a plain message saying why.
- It now covers address verification too. #396 made a verified address the default for resets, and
  the startup check refuses that with no `IEmailVerificationNotifier`, so the old quick start would
  no longer have started at all.

The issue suggested the package refuse to start "when the console notifier is registered". That
type only ever existed in the docs, so the package cannot see it; the guard lives in the snippet.

## Verified by running it

The `Program.cs` was extracted from the page as written and built as a fresh `dotnet new web` app
against the local projects. In Development: register 201, `/hello` 401 without a token and 200 with,
a reset for the unverified address prints nothing, verification works, a reset after it prints a
token, sign-in 200. In Production: startup throws the `ConsoleMail` message.

Two things tripped the first runs, neither in the page: `timeout` in this shell is Windows'
`timeout.exe`, and `dotnet new web` on an SDK 11 machine targets `net11.0`, so the build output was
not where the first script looked.
