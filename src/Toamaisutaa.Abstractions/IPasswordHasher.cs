namespace Toamaisutaa.Abstractions;

/// <summary>
/// Hashes and verifies passwords. Public so a consumer who is willing to take a third-party
/// dependency can register an Argon2id implementation instead of the shipped one; because the
/// stored string names its own algorithm and parameters, both can read each other's rows and the
/// fleet migrates itself through <see cref="PasswordVerificationResult.SucceededRehashNeeded"/>.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>A self-describing PHC string, for example
    /// <c>$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;</c>.</summary>
    string Hash(string password);

    /// <summary>Verifies against whatever algorithm and parameters the stored string names. Fails
    /// closed on anything it cannot parse or does not recognise.</summary>
    PasswordVerificationResult Verify(string password, string hash);
}

public enum PasswordVerificationResult
{
    Failed,

    Succeeded,

    /// <summary>Correct password, but stored with parameters weaker than the current configuration.
    /// The caller rehashes it while it has the plaintext in hand.</summary>
    SucceededRehashNeeded,
}
