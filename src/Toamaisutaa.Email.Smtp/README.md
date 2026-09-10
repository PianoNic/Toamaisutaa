# Toamaisutaa.Email.Smtp

SMTP notifiers for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa) password login - the reset
email, the invitation email, the password an admin issued, the email verification link and the
magic link. Optional - each notifier is a seam, and these are one implementation of them, not the
only valid one.

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
| `Email:Smtp:InvitationLinkTemplate` | | Required once invitation email is added, unless you register your own template. `{token}` is replaced with the raw invitation token |
| `Email:Smtp:SignInUrl` | none | Put at the end of the admin-issued password email when set |
| `Email:Smtp:EmailVerificationLinkTemplate` | | Required once email verification is added, unless you register your own template. `{token}` is replaced with the raw verification token |
| `Email:Smtp:MagicLinkTemplate` | | Required once magic link is added, unless you register your own template. `{token}` is replaced with the raw magic-link token |
| `Email:Smtp:Timeout` | `00:00:30` | |

All of the above are checked at startup, not at the first password reset request.

## The other four emails

`AddToamaisutaaSmtpEmail` sends the reset email and nothing else. The others are added one at a
time, on top of it:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);
builder.Services.AddToamaisutaaSmtpInvitationEmail();
builder.Services.AddToamaisutaaSmtpAdminPasswordEmail();
builder.Services.AddToamaisutaaSmtpEmailVerification();
builder.Services.AddToamaisutaaSmtpMagicLink();
```

They are separate calls because registering the notifier is what maps the endpoints at all: an
`IInvitationNotifier` maps `/auth/invitations`, an `IAdminPasswordIssuedNotifier` maps
`/auth/users`, an `IEmailVerificationNotifier` maps `/auth/email` and `/auth/email/verify`, and an
`IMagicLinkNotifier` maps `/auth/magic-link`. Installing this package to send reset mail should not
put a dozen endpoints on the wire that nobody asked for.

A magic link is only ever sent to a verified address, so `AddToamaisutaaSmtpMagicLink` needs
`AddToamaisutaaSmtpEmailVerification` (or an `IEmailVerificationNotifier` of your own) registered
as well. Startup refuses the pair without it.

## Replacing the wording

The subject and body come from `IPasswordResetEmailTemplate`, `IInvitationEmailTemplate`,
`IAdminPasswordIssuedEmailTemplate`, `IEmailVerificationEmailTemplate` and
`IMagicLinkEmailTemplate`. Register your own and it replaces the default outright - the transport
stays the same:

```csharp
builder.Services.AddSingleton<IPasswordResetEmailTemplate, YourTemplate>();
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);
```

## What it never does

Log the reset, invitation, verification or magic-link token, the issued password, the links they
appear in, or any part of any of them - not the value, not truncated, not at Debug. The email is
the only place those credentials are meant to exist in the clear.

## Documentation

**[Getting started](https://docs.toamaisutaa.pianonic.ch/getting-started)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
