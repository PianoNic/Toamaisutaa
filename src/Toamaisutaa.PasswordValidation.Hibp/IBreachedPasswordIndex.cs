namespace Toamaisutaa.PasswordValidation.Hibp;

internal interface IBreachedPasswordIndex
{
    /// <summary>Throws when the corpus cannot be reached; the caller decides to fail open.</summary>
    ValueTask<int> CountAsync(string password, CancellationToken cancellationToken = default);
}
