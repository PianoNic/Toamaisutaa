# Argon2id as a package, not as a default

Issue #66. `design/phase3-api-surface.md` recommended Konscious-backed Argon2id as the default
hasher; what shipped was PBKDF2 only, on the rule that nothing third-party belongs in the credential
path of a library other people install. Both positions were right about different things, and the
reconciliation is a separate package: `Toamaisutaa.PasswordHashing.Argon2`. Installing it is the
consumer making the dependency decision for themselves, which is the only place that decision
belongs.

## What it is

- `Argon2idPasswordHasher`, writing `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
- `AddToamaisutaaArgon2PasswordHashing`, bound to `PasswordHashing:Argon2`.
- A startup check that refuses parameters weaker than every OWASP configuration.
- Konscious 1.3.1, per the design record. Isopoh when its net10 build is published; the PHC format
  keeps that a one-file change.

## Decisions worth the record

**The hasher composes with the PBKDF2 one rather than replacing it.** `Argon2idPasswordHasher` takes
`Pbkdf2PasswordHasher` as a dependency and hands it every row that is not `$argon2id$`. That is what
makes the migration a rehash on next login: a deployment's existing rows verify exactly as they did,
and a correct password comes back as `SucceededRehashNeeded`, so the row is rewritten inside the
transaction that signed its owner in.

**`VerifyOnly` runs it backwards.** Reading Argon2id while writing PBKDF2 drains the rows the other
way, which is what makes the dependency reversible: uninstalling the package with Argon2id rows still
in the table leaves nothing that can read them, and there would otherwise be no way out that did not
end in a password reset for everybody. It is the escape hatch the design record argued the row format
already bought us, made operable.

**Registration uses `Replace`, not `TryAdd`.** `AddToamaisutaaPasswordLogin` adds the PBKDF2 hasher
with `TryAdd`, so with `TryAdd` on both sides the winner would be whichever call ran first. A package
installed for the hash and then quietly outvoted by the order of two lines in `Program.cs` is the
worst available outcome, so this one wins on purpose - and the startup check refuses to start if
something else was registered as `IPasswordHasher` after it, because that failure is otherwise
invisible.

**The OWASP floor is a table, not a number.** OWASP publishes five configurations as equivalent, from
46 MiB with one pass to 7 MiB with five. A single floor on memory would reject `m=47104,t=1`, which
is a legitimate choice; the check therefore passes anything at or above one of the five.

## Two changes outside the package

**`PhcString` learned an optional version segment.** Argon2's canonical encoding puts the version in
its own field - `$argon2id$v=19$m=...` - and the parser only accepted four. Writing `v` as another
parameter would have parsed with no change at all, and would have produced rows no other Argon2
implementation reads, which throws away the reason for using a standard format. PBKDF2 rows are
untouched: five segments, exactly as before.

**Pepper resolution moved to `PasswordPepper`.** Both hashers now share `Active`, `TryResolve` and
`Preprocess`. "Is this key still held, and is it the current one" is one rule, and its wrong answer
either accepts a password against a hash that was never made from it or locks a fleet out; two copies
of a rule like that drift into two answers. The Argon2 rows carry the version marker in the PHC
`keyid` field rather than in the algorithm name, because `$argon2id$` is what makes the row portable
and `$argon2id-p1$` would not be.

## What was left alone

`Pbkdf2PasswordHasher` still refuses `$argon2id$` rows. It cannot verify them without the dependency
this package exists to isolate, so the honest answer for a deployment that has uninstalled the
package while Argon2id rows remain is that it needs the package back, not a hasher that pretends.
