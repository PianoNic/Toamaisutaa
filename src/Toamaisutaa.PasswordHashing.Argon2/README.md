# Toamaisutaa.PasswordHashing.Argon2

Argon2id password hashing for [Toamaisutaa](https://github.com/PianoNic/Toamaisutaa). Optional - the
package hashes with PBKDF2 out of the box because nothing third-party belongs in the credential path
of a library you did not choose to install. This is that choice, made deliberately.

```bash
dotnet add package Toamaisutaa.PasswordHashing.Argon2
```

```csharp
builder.Services.AddToamaisutaaArgon2PasswordHashing(builder.Configuration);   // section "PasswordHashing:Argon2"
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

Before `AddToamaisutaaPasswordLogin` or after - registration order does not decide which hasher
wins, only that both calls run.

## Why

PBKDF2 is compute-hard and not memory-hard: each guess costs processor time and almost no memory,
which is the shape a rack of GPUs parallelises best. Argon2id makes every guess claim real memory
too. .NET has no in-box Argon2 and none is coming, so a memory-hard hash means someone else's
implementation - here
[Konscious](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2), pure managed,
no native assets, passing the RFC 9106 vectors.

## There is no migration

Rows a deployment already has are PBKDF2, and they keep verifying exactly as they did. A correct
password against one of them is answered with `SucceededRehashNeeded`, so the row is rewritten as
Argon2id in the same transaction that signed its owner in. The fleet migrates itself as people log
in; nothing to run, no flag day.

It runs backwards too. `PasswordHashing:Argon2:VerifyOnly` keeps reading Argon2id rows while writing
new ones with PBKDF2, so the rows drain the other way and the package can be uninstalled once the
last one is gone. Uninstalling it while Argon2id rows remain leaves nothing that can read them.

## Configuration

| Key | Default | Notes |
|---|---|---|
| `PasswordHashing:Argon2:MemorySizeKib` | `19456` | 19 MiB, the OWASP figure for two iterations |
| `PasswordHashing:Argon2:Iterations` | `2` | |
| `PasswordHashing:Argon2:DegreeOfParallelism` | `1` | Lanes divide the memory rather than add to it |
| `PasswordHashing:Argon2:VerifyOnly` | `false` | Read Argon2id, write PBKDF2 - the way back off this package |

Startup refuses anything weaker than every OWASP configuration - `m=47104,t=1`, `m=19456,t=2`,
`m=12288,t=3`, `m=9216,t=4`, `m=7168,t=5` - rather than hashing a real password with parameters that
cannot be repaired afterwards.

It refuses the other end as well: `m` above `1048576`, `t` above `64` or `p` above `64`. Those are
the bounds on what a stored row may ask this process for, so anything above them would be written
into rows the same hasher then refuses, and the correct password would come back as a wrong one.

Salt and output lengths come from `LocalLogin:SaltSizeBytes` and `LocalLogin:HashSizeBytes`, shared
with the PBKDF2 hasher. So does `LocalLogin:Pepper`: a peppered deployment stays peppered, and the
version marker rides along in the `keyid` field of the stored string.

## What a row looks like

```
$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
```

The standard PHC encoding, so the row says what made it and a parameter change is a rehash on next
login rather than a schema change.

## Documentation

**[Password hashing](https://docs.toamaisutaa.pianonic.ch/password-hashing)** -
[docs.toamaisutaa.pianonic.ch](https://docs.toamaisutaa.pianonic.ch)

Licensed under [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) -
free for noncommercial use; commercial use needs a separate licence.
