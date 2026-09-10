# Toamaisutaa.PasswordValidation.Hibp

A [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach check for
[Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) password login. Optional - `IPasswordValidator`
is a seam, and this is one implementation of it.

```bash
dotnet add package Toamaisutaa.PasswordValidation.Hibp
```

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
builder.Services.AddToamaisutaaHibpPasswordValidation(builder.Configuration);   // section "PasswordValidation:Hibp"
```

Registration order between the two does not matter, only that both run.

## What it adds, and what it leaves alone

It wraps the validator already registered rather than replacing it, so the length floor still
applies and still says what it said. A password that fails the length rules is refused without a
lookup - there is nothing to learn about a password nobody is going to end up with.

## Only five characters leave the process

The password is hashed with SHA-1 locally. The first five characters of that hash are sent to
`GET /range/{prefix}`, which answers with every suffix sharing it - on the order of eight hundred -
and the comparison against the other thirty-five characters happens in your process. The service
learns that somebody typed one of eight hundred things, and nothing about which. The request also
asks for a padded response, so its length says nothing either.

SHA-1 is not a security choice here. It is the corpus's index, and nothing about a password is
recoverable from five hex characters of it.

## It fails open

If the range API is unreachable, times out, or answers with something unexpected, the password is
accepted and a warning is logged. A third party being down must not be the reason nobody in your
deployment can register or change a password. If that trade is wrong for you, mirror the
downloadable corpus and point `ApiBaseAddress` at it.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `PasswordValidation:Hibp:BreachThreshold` | `1` | Appearances in the corpus that refuse the password. `1` refuses anything it has ever seen |
| `PasswordValidation:Hibp:ApiBaseAddress` | `https://api.pwnedpasswords.com/` | Point it at your own mirror to keep the lookup on your network |
| `PasswordValidation:Hibp:Timeout` | `00:00:03` | Short on purpose: this sits in front of every registration and password change |
| `PasswordValidation:Hibp:UserAgent` | `Toamaisutaa` | The range API refuses requests without one. Name your application |
| `PasswordValidation:Hibp:Message` | see below | What the person choosing the password is told |

The default message is "That password has appeared in a known data breach. Choose a different one."

All of the above are checked at startup, not at the first password anybody chooses.

## Putting a handler in front of the lookup

The lookup uses a named `HttpClient`, so a retry policy or an outbound proxy goes on without
replacing the validator:

```csharp
builder.Services.AddHttpClient(ToamaisutaaHibpDefaults.HttpClientName)
    .AddStandardResilienceHandler();
```

## What it never does

Send, log, or store the password, the whole hash, or any part of either beyond the five-character
prefix that the lookup is made of. The warning it writes when the service is unreachable names the
address it could not reach and nothing else.

## Documentation

**[Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
