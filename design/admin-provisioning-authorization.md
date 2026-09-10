# Admin provisioning: who may call it, and what a failed notifier answers

The record for issue #106. Three decisions here are not the obvious ones.

## Not mapped, rather than mapped and refusing

`POST /auth/users`, `POST /auth/users/{userId}/password` and `POST /auth/invitations` now carry
`Toamaisutaa.Admin` instead of a bare `.RequireAuthorization()`, which resolved to the default
policy: `RequireAuthenticatedUser` and nothing else. The target came from the route, so any account
that could sign in could overwrite any other account's password and then sign in as it. A test on
main asserted that as correct behaviour.

The policy only exists when `Oidc:AdminRole` is set, so `.RequireAuthorization("Toamaisutaa.Admin")`
against an unconfigured application would throw on the first request to those routes rather than at
startup. Three ways out were on the table:

1. Register the policy always, refusing everyone when no role is named. Safe, but the failure is a
   403 with no way to tell "you are not an admin" from "nobody here is".
2. Refuse to start. Wrong layer: `AdminSetPasswordAsync` is legitimate from a worker with no
   authorization stack at all, and the check would have to live in Core, which cannot know whether
   anything is being mapped.
3. Do not map them, and say so once at startup.

Three, because the package already answers "this feature is not configured" that way twice -
`/auth/register` under `AllowSelfRegistration`, and every notifier-gated pair. The unmapping is
silent enough to be mistaken for a typo in a path, so a warning names the missing setting. This is
the one behavioural break for an existing consumer: an application that registered a provisioning
notifier and never set `Oidc:AdminRole` had these endpoints and now does not. It had them open to
every signed-in caller, which is the reason to take them away rather than a cost of doing so.

`POST /auth/invitations/complete` stays mapped without an admin role. It is redeemed by the invited
person against a token, and the invitation may have been created by a worker calling
`CreateInvitationAsync` directly.

## 502, and why not 500 or 204

`AdminSetPasswordAsync` awaited the notifier between committing the new hash and revoking anything.
A relay outage skipped the stamp bump, the sessions, the devices, the reset tokens and the event,
and answered 500 - so an account reset in order to lock somebody out kept them signed in, under a
password nobody knew. The revocation now runs first and the notifier is wrapped.

The reset path answers 204 for the same failure, because telling a caller that delivery failed
would tell them the address exists. That reasoning does not carry here: the caller is an
administrator acting on an id they already have, so there is nothing to leak, and silence would be
worse than useless - a generated password that reached nobody is an account only another call to
this method can open. Hence a status of its own. 502 rather than 500 because the request was
carried out and the dependency behind it is what failed, and rather than 200-with-a-warning because
a client branching on success would file this under "sent".

## Rolled back, rather than reported and left

`CreateInvitationAsync` had the same unguarded await, but the right answer is the opposite one:
nothing there looks for an existing reservation before calling `users.CreateAsync`, so leaving the
row behind means every retry against a still-down relay reserves the address again. The token is
marked consumed and then the user row is deleted - the token row goes with it through the cascade
on `ToamaisutaaInvitationToken.UserId`, and burning it first means an `IInvitationTokenStore` that
does not cascade still leaves nothing redeemable. `AccountResult.NotificationFailed` is therefore
independent of `Succeeded`: true and true for the password path, false and true here.

## Left alone

`AdminCreateAccountAsync` awaits `IAdminPasswordIssuedNotifier` unguarded in exactly the same shape,
at what is now roughly line 191. It is out of scope for #106 and wants its own change: unlike the
two above it has a third option, since the account it just created has no sessions and no history,
so deleting it is a real rollback rather than a lie.
