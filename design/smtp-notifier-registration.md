# Why the SMTP invitation and admin-password notifiers are separate calls

Issue #61 asked for SMTP implementations of `IInvitationNotifier` and `IAdminPasswordIssuedNotifier`
"registered with `TryAdd` so an implementation the consumer registers still wins", which reads as
three `TryAddSingleton` lines inside `AddSmtpEmailCore`. They are three separate registration calls
instead:

```csharp
builder.Services.AddToamaisutaaSmtpEmail(builder.Configuration);   // the reset email
builder.Services.AddToamaisutaaSmtpInvitationEmail();
builder.Services.AddToamaisutaaSmtpAdminPasswordEmail();
```

`MapToamaisutaaPasswordEndpoints` decides whether `/auth/users`, `/auth/users/{userId}/password`,
`/auth/invitations` and `/auth/invitations/complete` exist at all by asking the container whether an
`IAdminPasswordIssuedNotifier` and an `IInvitationNotifier` are registered. That is the whole opt-in
gate for admin provisioning, and it is the same reasoning `/auth/register` uses for
`AllowSelfRegistration`.

Registering both notifiers from `AddToamaisutaaSmtpEmail` would therefore flip that gate as a side
effect of installing a package for reset mail: four endpoints appear on the wire, two of them able
to create accounts and overwrite other people's passwords, in an application that never asked for
them. `RequireAuthorization()` on those endpoints means any authenticated user, not any
administrator, so the answer to "who can now do this" would be "everybody who can sign in".

A DI registration silently changing a routing decision is the kind of thing nobody looks for when
reading a diff that says "add SMTP email". Splitting the calls keeps the gate where it already was:
one deliberate line per capability.

Two smaller decisions that followed from it:

- `SmtpInvitationStartupCheck` is its own hosted service rather than more branches in
  `SmtpEmailStartupCheck`, because `Email:Smtp:InvitationLinkTemplate` is only required when
  invitation email was actually opted into. It also skips validation entirely when the registered
  `IInvitationEmailTemplate` is not the default one, since the link is the default template's
  business alone.
- The admin-password email needs no required option, so it gets no startup check.
  `Email:Smtp:SignInUrl` is optional and is appended only when set: a credentials email is still
  useful without it, and the person reading one was usually told what they are signing in to by
  whoever provisioned the account.
