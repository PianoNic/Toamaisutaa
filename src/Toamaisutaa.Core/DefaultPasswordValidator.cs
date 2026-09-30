using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Enforces a minimum and maximum length and nothing else, following NIST guidance against
/// composition rules. A custom validator can call it for the length part and add a breach-list check.
/// </summary>
public sealed class DefaultPasswordValidator(IOptions<ToamaisutaaLocalLoginOptions> options) : IPasswordValidator
{
    public IReadOnlyList<string> Validate(string password)
    {
        var settings = options.Value;

        if (string.IsNullOrEmpty(password) || password.Length < settings.MinimumPasswordLength)
            return [$"Use at least {settings.MinimumPasswordLength} characters."];

        // Not a strength rule: HMAC reduces anything past its block size anyway, and an unbounded
        // field on an anonymous endpoint spends the server's memory and CPU.
        if (password.Length > settings.MaximumPasswordLength)
            return [$"Use at most {settings.MaximumPasswordLength} characters."];

        return [];
    }
}
