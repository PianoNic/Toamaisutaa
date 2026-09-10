# Toamaisutaa.PasswordValidation.Hibp: the decisions worth the record

Written after implementing issue #69, and added to as the package was corrected. The package itself
is documented for consumers at `docs/breached-passwords.md`; this is the part a consumer never needs
and a maintainer does.

---

## 1. `IPasswordValidator` had no way to answer a question that needs the network

`IPasswordValidator.Validate` is synchronous, and every implementation until now decided from the
string in front of it. A breach check cannot: it is an HTTP round trip, and it sits on
`/auth/register`, an anonymous endpoint that anybody can drive.

Three ways out were available.

**Block inside `Validate`.** `GetAwaiter().GetResult()` on every registration and every password
change, on the request thread, with a third party at the other end. No deadlock in ASP.NET Core -
there is no synchronisation context - but it holds a thread pool thread for the whole round trip on
the one path an attacker can call without credentials. Rejected as the default path.

**A second interface.** `IAsyncPasswordValidator`, resolved in preference to the first. Two seams
where the docs promise one, and the failure mode is a consumer registering the wrong one and getting
a validator that is never called - silently, because a validator that is not consulted looks exactly
like one that approves.

**A default interface method.** Taken:

```csharp
ValueTask<IReadOnlyList<string>> ValidateAsync(string password, CancellationToken cancellationToken = default) =>
    ValueTask.FromResult(Validate(password));
```

Nothing already written breaks - a validator that decides locally implements `Validate` and inherits
the rest - and there is still one seam. `PasswordAccountService` now awaits `ValidateAsync` at all
six call sites; every one was already inside an async method with a cancellation token in scope, so
no sync-over-async exists in the package's own path.

`HibpPasswordValidator` still implements `Validate`, and it blocks. Nothing in the package reaches
it, and the alternative - throwing - punishes a consumer holding the interface from somewhere
synchronous for a decision this package made.

**The risk this leaves.** A future call site that chooses a password and calls `Validate` compiles,
passes, and skips the breach check without a word. `AsyncPasswordValidatorTests` asserts one path
per public method against a validator that answers only from `ValidateAsync`, which is what makes
that mistake red rather than quiet. It was watched failing on all six.

---

## 2. Composing rather than replacing, without a registration order to remember

The issue asks for composition with the default validator. The container makes that awkward: the
validator is a single `IPasswordValidator`, `AddToamaisutaaPasswordLogin` registers the default with
`TryAdd`, and a decorator cannot depend on the thing it replaces.

What the extension does is take the descriptor:

```csharp
var existing = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IPasswordValidator));
if (existing is not null)
    services.Remove(existing);
```

and rebuild what it described - instance, factory or implementation type - as the wrapped validator.

This makes both registration orders work, and for a reason worth stating because it is not obvious:

- **Hibp after `AddToamaisutaaPasswordLogin`.** It finds `DefaultPasswordValidator` and wraps it.
- **Hibp before.** It finds nothing, so it builds `DefaultPasswordValidator` itself - which is the
  whole reason this package references `Toamaisutaa.Core` - and the `TryAdd` inside
  `AddToamaisutaaPasswordLogin` then sees an `IPasswordValidator` already standing and leaves it
  alone.
- **A validator of your own, registered first.** It wraps yours, not the default. Somebody who
  replaced the length rules deliberately does not want them back.

The `Remove` matters on its own: leaving the wrapped descriptor in the collection would put two
registrations of one service in the container and make which one you get a question about ordering.
`LeavesExactlyOneValidatorRegistered` covers it, and was watched failing.

## 3. The wrapped validator goes back into the container, it is not rebuilt by hand

Rebuilding the descriptor by hand was wrong in a way that took a while to surface. The wrapper was
registered with `AddSingleton`, so the `IServiceProvider` its factory received was the root
provider, and `ResolveInner` never read `descriptor.Lifetime`. A validator of somebody's own
registered `AddScoped` was therefore built once, from the root, for the life of the process:

- with scope validation on, the first password answers 500 naming *their* scoped dependency, with
  nothing to say that installing this package caused it;
- with it off, that dependency is captured and shared across every concurrent request;
- and `ActivatorUtilities.CreateInstance` registers nothing for disposal, so an `IDisposable`
  validator was never disposed.

The descriptor now goes back into the collection under a key of its own, and the wrapper is
registered with the lifetime that descriptor carried:

```csharp
var innerKey = new object();
var inner = InnerDescriptor(existing, innerKey);
services.Add(inner);
services.Add(new ServiceDescriptor(typeof(IPasswordValidator), provider => new HibpPasswordValidator(
    provider.GetRequiredKeyedService<IPasswordValidator>(innerKey), ...), inner.Lifetime));
```

The container builds the wrapped validator, from the scope that asked for it, and disposes it. The
key is a fresh `object` per call rather than a constant, so a second registration wraps the first
wrapper instead of resolving itself, and the search for the descriptor to wrap ignores keyed ones -
somebody else's keyed validator is theirs. `LeavesExactlyOneValidatorRegistered` now counts unkeyed
registrations, which is what "the one everybody resolves" meant all along.

## 4. A base address without a trailing slash is not a configuration error

`new Uri(new Uri(baseAddress), "range/{prefix}")` is relative resolution, so it replaces the last
path segment: a mirror configured as `https://mirror.internal/pwned` was asked for
`https://mirror.internal/range/{prefix}`. That 404s, the fail-open handler accepts the password, and
the warning names the address as configured rather than the one that was requested - so a deployment
that thinks it checks breaches accepts `password`, and the only evidence points at the wrong URL.

Two options: refuse to start on the slashless form, or keep the path. Keeping it won. There is no
second reading of `https://mirror.internal/pwned` - nobody means "drop `/pwned`" - so refusing to
start would be the package insisting on a punctuation mark it can supply itself. The startup check
does now insist on `http` or `https`, because `file:` and `ftp:` parse as absolute URIs and then
fail every lookup on a scheme `HttpClient` will not send, and there the intent really is unusable.

---

## What was deliberately not built

- **No health check and no startup probe of the range API.** The package fails open by design, so a
  probe could only report something it has already decided not to act on, and it would put a network
  call in the startup path of every deployment that installs this.
- **No caching of range responses.** A prefix answer is ~800 lines and the password being checked is
  usually new, so the hit rate is near zero and the thing being cached is derived from a credential.
- **No offline corpus support in the package.** `ApiBaseAddress` points at a mirror instead, which
  keeps the package to one code path and puts the choice of how to host 850 million hashes with
  whoever wants to host them.
