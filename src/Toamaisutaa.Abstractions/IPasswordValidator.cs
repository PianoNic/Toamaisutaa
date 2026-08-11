namespace Toamaisutaa.Abstractions;

/// <summary>
/// Decides whether a password may be used. The shipped implementation enforces a length floor and
/// nothing else, per NIST; replace it to add a breach-list check or your own policy.
/// </summary>
public interface IPasswordValidator
{
    /// <summary>Empty when the password is acceptable. Messages are shown to the person choosing
    /// it, so they should say what to do rather than what went wrong.</summary>
    IReadOnlyList<string> Validate(string password);
}
