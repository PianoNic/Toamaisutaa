namespace Toamaisutaa.PasswordHashing.Argon2;

/// <summary>
/// Everything read from the <c>PasswordHashing:Argon2</c> configuration section. The defaults are
/// the OWASP baseline, and startup refuses anything weaker than the weakest configuration OWASP
/// considers equivalent to it.
/// </summary>
/// <remarks>
/// The salt and output lengths are not here: they are <c>LocalLogin:SaltSizeBytes</c> and
/// <c>LocalLogin:HashSizeBytes</c>, shared with the PBKDF2 hasher, because a deployment that has
/// decided how long a salt is has decided it for both.
/// </remarks>
public sealed class ToamaisutaaArgon2Options
{
    /// <summary>Memory per hash, in kibibytes. 19456 is 19 MiB, the OWASP figure for
    /// <see cref="Iterations"/> = 2.</summary>
    public int MemorySizeKib { get; set; } = 19_456;

    /// <summary>Passes over that memory. Trading it against <see cref="MemorySizeKib"/> is how
    /// OWASP's configurations differ from one another.</summary>
    public int Iterations { get; set; } = 2;

    /// <summary>Lanes. OWASP fixes this at 1: it divides the same memory rather than adding to
    /// it, so raising it is not a strength dial.</summary>
    public int DegreeOfParallelism { get; set; } = 1;

    /// <summary>
    /// Keeps reading Argon2id rows but writes new ones with PBKDF2. Off by default.
    /// </summary>
    /// <remarks>
    /// The way back off this package. Every correct password stored as Argon2id is answered with a
    /// rehash, so the rows drain to PBKDF2 as people sign in, and once the last one is gone the
    /// package can be uninstalled without locking anybody out. Uninstalling it while Argon2id rows
    /// remain leaves nothing that can read them.
    /// </remarks>
    public bool VerifyOnly { get; set; }
}
