# Customizing local password login

Three seams, each swapped by registering your own implementation before
`AddToamaisutaaPasswordLogin`. See also [password hashing](/password-hashing) for `IPasswordHasher`,
the fourth.

## The password rules are a length floor, and a seam

`MinimumPasswordLength` and `MaximumPasswordLength` are the whole of the built-in policy, following
NIST: a length floor and no composition rules, because "one uppercase, one digit, one symbol"
reliably produces `Password1!` and nothing safer.

If you need something else - a zxcvbn score, a rule about your organisation's name, your own wording
on the message the user sees - register an `IPasswordValidator` and it replaces the default outright:

```csharp
builder.Services.AddSingleton<IPasswordValidator, YourPasswordValidator>();
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

The strings it returns reach the caller in the `errors` array, so write them for the person typing.

`Validate` is the only method you have to write. `ValidateAsync` is what the package actually calls,
and it defaults to `Validate` - implement it instead when the answer needs I/O, and the cancellation
token is the caller's.

For the breach-list check specifically, there is a package: see
[breached passwords](/breached-passwords). It wraps whatever validator is registered rather than
replacing it, so the length rules survive.

## What goes in the access token is a seam too

`IAccessTokenIssuer` mints the locally issued token: the claims, the lifetime, the signature.
Replace it when you need a claim this package does not add.

Asymmetric signing is not a reason to replace it any more: set `LocalLogin:SigningKeys` and the
package signs with an RSA or EC key and publishes the public half itself - see
[signing local tokens](/token-signing).

```csharp
builder.Services.AddSingleton<IAccessTokenIssuer, YourTokenIssuer>();
```

If you add a claim, read [what `RefreshAsync` has to answer for](/password-login#a-new-claim-and-the-refresh-path)
before you ship it.

## Local accounts have no roles

This package has no roles table, so a locally issued token carries no role claims and satisfies no
role requirement, including `Oidc:AdminRole`. Register an `IUserRoleProvider` to supply them from
wherever your roles actually live.

```csharp
builder.Services.AddSingleton<IUserRoleProvider, YourRoleProvider>();
```

This is what a local account needs before it can reach the
[admin provisioning endpoints](/provisioning-accounts#the-three-admin-endpoints-need-an-admin-role),
which ask for the role `Oidc:AdminRole` names.
