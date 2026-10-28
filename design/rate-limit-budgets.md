# Rate-limit budgets (#391)

One fixed window per address covered every anonymous endpoint and the signed-in ones too, so a
school behind one public address shared ten requests a minute between everyone in it.

## Re-verified

- The per-address limit was already configurable (`RateLimit:PermitLimit`). That part of the issue
  did not hold.
- Budgets are in process memory. True, and documented rather than changed: a distributed limiter is
  the gateway's job, and a store-backed one here would put a database write in front of every login.

## What changed

- **A signed-in caller spends its own budget**, keyed on `sub`, wherever the endpoint requires the
  sign-in. Not on an anonymous endpoint: there any token would buy a fresh budget, and a throwaway
  account would become a guessing allowance. The first version of the test for that could not tell
  the two apart, because both budgets had the same limit; it now spends the address budget first.
- **`RateLimit:SharedNetworks`** with `SharedNetworkPermitLimit` (300). A caller inside one spends the
  network's budget, and neither its own address's nor its IPv6 /48's. Unparsable entries fail startup.

## Not added: a per-identifier limit

The issue suggested one so the address limit could be raised safely. #390's account-wide lockout
ceiling already caps wrong passwords per account across all sources, which is that limit for every
account that exists. An identifier with no account costs a dummy hash and nothing else, and the
address budget is what bounds that.

## Verification

Five mutations, each reddening its own test; the anonymous-endpoint one only after the test was fixed
as above.
