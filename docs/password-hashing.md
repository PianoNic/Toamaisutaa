# Password hashing

## Why not just SHA-256?

It is SHA-256. PBKDF2-HMAC-SHA256 is SHA-256 run 600,000 times in a chain, where each round's output
feeds the next, so there is no way to skip to the end.

That chain is the entire feature. A single SHA-256 is built to be fast, and fast is the wrong
property for a password: commodity hardware does billions of SHA-256 operations a second, so a
stolen table of single-round hashes is a dictionary attack that finishes over lunch. Six hundred
thousand rounds makes one guess cost about a tenth of a second. Nobody notices that once at sign-in;
an attacker working through a word list notices it every single time.

The salt handles the other half. Without one, identical passwords produce identical hashes, so
cracking one row cracks every account that shares that password and a precomputed table works
against everybody at once. With one, each row has to be attacked on its own.

### The rule underneath

This codebase uses both. Passwords go through 600,000 rounds of PBKDF2 with a salt; refresh tokens,
password reset tokens and recovery codes are stored as a **plain, unsalted, single-round SHA-256**.
That is not an inconsistency, and the deciding question is always the same one:

**Does the input have entropy of its own?**

- **Passwords do not.** People choose them, from a space small enough to enumerate. The hash has to
  supply the cost that the input does not, which is what iteration buys - and a salt, because
  low-entropy inputs collide across users.
- **Tokens do.** They are 256 bits straight from the system random generator. There is no dictionary
  to try, so iteration defends against nothing; no two can collide, so a salt has nothing to do. All
  that is left is looking one up by exact match on every request, which a fast hash does well and a
  slow one would turn into a per-request cost buying nothing.

So: slow and salted when a human picked it, fast and plain when the random generator did. Reach for
the expensive one by default, and be able to say why when you do not.

## Where PBKDF2 stops

PBKDF2 is **compute-hard but not memory-hard**: each guess costs processor time and almost no memory,
which is the shape an attacker with a rack of GPUs is best equipped to parallelise. A memory-hard
function - Argon2id is the usual choice - makes each guess claim real memory too, and that is
materially harder to run thousands of at once. If you are protecting credentials whose loss would be
serious, that difference is worth having.

It is not the default here for a dependency reason rather than a cryptographic one. PBKDF2 is in the
base class library; .NET has no in-box Argon2, and none is coming, because the runtime delegates
primitives to the platform and only OpenSSL implements it. Taking a third-party package into the
credential path of a library other people install is a decision this package will not make on your
behalf.

So it is your decision, in one line.

## Argon2id, in an opt-in package

```bash
dotnet add package Toamaisutaa.PasswordHashing.Argon2
```

```csharp
builder.Services.AddToamaisutaaArgon2PasswordHashing(builder.Configuration);   // section "PasswordHashing:Argon2"
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

Before `AddToamaisutaaPasswordLogin` or after: registration order does not decide which hasher wins.
The dependency it carries -
[Konscious](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2), pure managed and
passing the RFC 9106 vectors - is installed with the package and reaches nothing else.

| Key | Default | Notes |
|---|---|---|
| `PasswordHashing:Argon2:MemorySizeKib` | `19456` | 19 MiB, the OWASP figure for two iterations |
| `PasswordHashing:Argon2:Iterations` | `2` | |
| `PasswordHashing:Argon2:DegreeOfParallelism` | `1` | Lanes divide the memory rather than add to it |
| `PasswordHashing:Argon2:VerifyOnly` | `false` | Read Argon2id, write PBKDF2 - the way back off the package |

Startup refuses anything weaker than every OWASP configuration - `m=47104,t=1`, `m=19456,t=2`,
`m=12288,t=3`, `m=9216,t=4`, `m=7168,t=5` - rather than let a real password be hashed under
parameters that cannot be repaired afterwards. Salt and output lengths stay
`LocalLogin:SaltSizeBytes` and `LocalLogin:HashSizeBytes`, and a configured `LocalLogin:Pepper` keeps
applying.

It refuses the other end as well: `m` above `1048576`, `t` above `64` or `p` above `64`. A stored
row may not ask this process for more than that, so a value above one of those bounds would be
written into rows and then refused by the same hasher, and the correct password would come back as
a wrong one. `LocalLogin:HashSizeBytes` has the same ceiling of `1024` for both hashers.

### There is no migration, in either direction

Every stored hash is a PHC string naming the algorithm and parameters that produced it:

```
$pbkdf2-sha256$i=600000$<salt>$<hash>
$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
```

So the rows a deployment already has keep verifying, and each one is rewritten as Argon2id on that
user's next successful sign-in. Nothing to run, no flag day, and nobody locked out.

Setting `VerifyOnly` runs the same thing backwards: Argon2id rows still verify, new ones are written
with PBKDF2, and once the last Argon2id row has drained the package can be uninstalled. Uninstalling
it while Argon2id rows remain leaves nothing that can read them.

## Or bring your own

`IPasswordHasher` is a seam, and the Argon2 package is one implementation of it rather than the only
one allowed. Register your own and it wins:

```csharp
builder.Services.AddSingleton<IPasswordHasher, YourHasher>();
builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
```

The same rehash-on-next-login path carries your rows too, as long as what you write says what made
it.

## A pepper is available, and off by default

Set `LocalLogin:Pepper` to a base64 secret of at least 32 bytes and passwords are reduced through
`HMAC-SHA256(pepper, password)` before derivation. Its entire value is that it does not live in the
database, so keep it where the database credentials do not reach.

Rotate by moving the old key into `LocalLogin:RetiredPeppers` under its version marker and setting a
new `Pepper` and `PepperVersion`; rows rewrite themselves as people log in. Lose it with no retired
copy and every password becomes unverifiable.
