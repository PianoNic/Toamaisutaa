# Breached-password checking

The built-in rules are a length floor and nothing else, following NIST. The one thing NIST does ask
for beyond length is a check against known-breached passwords, and
`Toamaisutaa.PasswordValidation.Hibp` is that check, shipped as its own package because it is the one
part of choosing a password that leaves your process.

```bash
dotnet add package Toamaisutaa.PasswordValidation.Hibp
```

```csharp
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
builder.Services.AddToamaisutaaHibpPasswordValidation(builder.Configuration);   // section "PasswordValidation:Hibp"
```

Order between the two does not matter, only that both run.

It applies everywhere a password is chosen: `/auth/register`, `/auth/password`,
`/auth/password/reset`, `/auth/invitations/complete`, and the admin endpoints. A refused password
comes back the way any other refused password does - `400` with the message in `errors`:

```json
{
  "errors": ["That password has appeared in a known data breach. Choose a different one."]
}
```

## It is added to the length rules, not put in their place

Registering it wraps whatever validator is already there rather than replacing it, so
`MinimumPasswordLength` and `MaximumPasswordLength` still apply and still say what they said. If you
registered an `IPasswordValidator` of your own, it wraps yours.

A password the length rules already refused is never looked up. There is nothing to learn about a
password nobody is going to end up with, and asking would spend a request on every short password
typed into an anonymous endpoint.

## Five characters, and that is all that leaves

The password is hashed with SHA-1 in your process. The first five characters of that hash go to
`GET https://api.pwnedpasswords.com/range/{prefix}`, which answers with every suffix sharing the
prefix - several hundred of them - and the comparison against the remaining thirty-five characters
happens locally. The service learns that somebody typed one of several hundred things and nothing
about which one. The request also asks for a padded response, so the number of entries coming back
says nothing either.

SHA-1 is not a security choice here. It is the index the corpus is published under, and nothing
about a password is recoverable from five hex characters of it. Your passwords are still stored the
way [password hashing](/password-hashing) describes.

## It fails open

If the range API is unreachable, times out, or answers with something unexpected, the password is
accepted and a warning is logged naming the address that could not be reached.

That is a deliberate trade. This is a second opinion on a password the length rules already
accepted, and a third party being down must not be the reason nobody in your deployment can
register or change their password. If the trade is wrong for you, do not turn it off - mirror the
[downloadable corpus](https://haveibeenpwned.com/Passwords) on your own network and point
`ApiBaseAddress` at it, so there is no third party in the path to be down.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `PasswordValidation:Hibp:BreachThreshold` | `1` | Appearances in the corpus that refuse the password. `1` refuses anything it has ever seen |
| `PasswordValidation:Hibp:ApiBaseAddress` | `https://api.pwnedpasswords.com/` | Point it at your own mirror to keep the lookup on your network |
| `PasswordValidation:Hibp:Timeout` | `00:00:03` | Short on purpose: this sits in front of every registration and password change |
| `PasswordValidation:Hibp:UserAgent` | `Toamaisutaa` | The range API refuses requests without one. Name your application |
| `PasswordValidation:Hibp:Message` | the message above | What the person choosing the password is told |

All of them are checked at startup, not at the first password anybody chooses.

### Raising the threshold

`1` refuses every password the corpus has ever seen, which is the safe default and occasionally
surprising: long, memorable passphrases do turn up in it once. Raising it to something like `10`
keeps the passwords everybody uses out while tolerating the long tail.

```json
{
  "PasswordValidation": {
    "Hibp": {
      "BreachThreshold": 10,
      "UserAgent": "your-application-name"
    }
  }
}
```

## Putting a handler in front of the lookup

The lookup goes through a named `HttpClient`, so a retry policy or an outbound proxy goes on without
replacing the validator:

```csharp
builder.Services.AddHttpClient(ToamaisutaaHibpDefaults.HttpClientName)
    .AddStandardResilienceHandler();
```

## Writing your own instead

`IPasswordValidator` is still the seam, and this package is one implementation of it. If you want a
zxcvbn score, a corpus of your own, or a rule about your organisation's name, see
[customizing local login](/customizing-password-login). Note `ValidateAsync`: that is the method the
package calls, and the one to implement when the answer needs I/O.
