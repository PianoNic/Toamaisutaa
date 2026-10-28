# Warning when an email change takes an address from another account (#395)

An account may ask for an address another account holds unverified, because a proven claim outranks
an unproven one (otherwise anyone could register someone else's address first and lock them out).
The verification mail goes to that address, whose owner is often the other account: someone who
registered with their own address and never verified it. They read "confirm that this address
belongs to your account", recognise their own address, click, and it moves to the asker.

## The issue's suggestion, and why not

It suggested naming the requesting account in the mail. The template deliberately names nobody: a
user name is whatever the asker typed, and this mail goes to somebody else's inbox, so naming it lets
anyone send their own words from this domain to any address. That reason still holds.

## What changed instead

- `IEmailVerificationNotifier` and `IEmailVerificationEmailTemplate` each gained an overload taking
  `EmailVerificationContext`. The defaults drop the context, so existing implementations keep working
  and send the old message.
- `RequestEmailChangeAsync` sets `TakesFromAnotherAccount` when the address is held, unproven, by a
  different account, and calls the context overload.
- The SMTP template sends a different message in that case: somebody wants this address on their
  account, it is currently on another one which may be yours, using the link moves it away, do not
  use it unless you asked. No name.
- `EmailAddressReleased` is published for the account that lost the address, with the address and
  who took it, so a sink can tell that account. Its email is read before the release clears it on
  the same instance; the first test run caught the event carrying the normalised address.

## Verification

Six mutations across Core and SMTP, each reddening its own test. One full-suite run hit a timing flake
in `Hung_jobs_count_against_the_limit_after_they_are_abandoned` (mail queue, untouched here); it passed
five runs alone and the next full run.
