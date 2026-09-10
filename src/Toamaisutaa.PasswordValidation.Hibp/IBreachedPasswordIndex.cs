namespace Toamaisutaa.PasswordValidation.Hibp;

/// <summary>How many times a password appears in a corpus of breached credentials.</summary>
/// <remarks>
/// Internal, and staying that way: the swappable thing here is <c>IPasswordValidator</c>, which is
/// already a public seam. This exists so the validator's decisions can be tested without a network,
/// and so the wire format lives in one place.
/// </remarks>
internal interface IBreachedPasswordIndex
{
    /// <summary>Throws when the corpus cannot be reached. The caller decides what an unreachable
    /// corpus means, and it decides to let the password through.</summary>
    ValueTask<int> CountAsync(string password, CancellationToken cancellationToken = default);
}
