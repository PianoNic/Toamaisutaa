# Toamaisutaa.Email.Smtp

An SMTP `IPasswordResetNotifier` for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) password
login. Optional - the notifier is a seam, and this is one implementation of it, not the only valid
one.

```bash
dotnet add package Toamaisutaa.Email.Smtp
```

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // section "Email:Smtp"
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

Call it before `AddToamaisutaaPasswordLogin` or after - registration order between the two does not
matter, only that both run.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `Email:Smtp:Host` | | Required |
| `Email:Smtp:Port` | `587` | |
| `Email:Smtp:User` / `Password` | none | Omit `User` for an unauthenticated relay |
| `Email:Smtp:Security` | `Auto` | `None`, `StartTls`, `SslOnConnect`, or `Auto` (TLS on 465, STARTTLS otherwise) |
| `Email:Smtp:SkipCertificateVerification` | `false` | For a self-signed relay on a private network only |
| `Email:Smtp:From` | | Required, a valid email address |
| `Email:Smtp:FromDisplayName` | none | |
| `Email:Smtp:PasswordResetLinkTemplate` | | Required unless you register your own template. `{token}` is replaced with the raw reset token |
| `Email:Smtp:Timeout` | `00:00:30` | |

All of the above are checked at startup, not at the first password reset request.

## Replacing the wording

The subject and body come from `IPasswordResetEmailTemplate`. Register your own and it replaces the
default outright - the transport stays the same:

```csharp
builder.Services.AddSingleton<IPasswordResetEmailTemplate, YourTemplate>();
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);
```

## What it never does

Log the reset token, the link it appears in, or any part of either - not the value, not truncated,
not at Debug. The email is the only place that credential is meant to exist in the clear.

## Documentation

**[Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
