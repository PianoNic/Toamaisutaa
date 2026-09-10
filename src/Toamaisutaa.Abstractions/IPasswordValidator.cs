namespace Toamaisutaa.Abstractions;

/// <summary>
/// Decides whether a password may be used. The shipped implementation enforces a length floor and
/// nothing else, per NIST; replace it for your own policy, or install
/// <c>Toamaisutaa.PasswordValidation.Hibp</c> for a breach-list check on top of it.
/// </summary>
public interface IPasswordValidator
{
    /// <summary>Empty when the password is acceptable. Messages are shown to the person choosing
    /// it, so they should say what to do rather than what went wrong.</summary>
    IReadOnlyList<string> Validate(string password);

    /// <summary>
    /// What the package actually calls. Defaults to <see cref="Validate"/>, so a validator that
    /// decides locally implements the one method and ignores this.
    /// </summary>
    /// <remarks>
    /// Override it when the answer needs I/O - a breach-list lookup is the case this exists for.
    /// Every call site is already inside an async method with a cancellation token in scope, so
    /// there is no sync-over-async anywhere in the package's own path.
    /// </remarks>
    ValueTask<IReadOnlyList<string>> ValidateAsync(string password, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Validate(password));
}
