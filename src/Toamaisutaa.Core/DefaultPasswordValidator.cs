using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// A length floor, a length ceiling, and nothing else. Following NIST: composition rules push
/// people towards predictable substitutions and forced rotation towards incrementing a digit.
/// Public so a consumer's own validator can call it for the length part and add a breach-list
/// check.
/// </summary>
public sealed class DefaultPasswordValidator(IOptions<ToamaisutaaLocalLoginOptions> options) : IPasswordValidator
{
    public IReadOnlyList<string> Validate(string password)
    {
        var settings = options.Value;

        if (string.IsNullOrEmpty(password) || password.Length < settings.MinimumPasswordLength)
            return [$"Use at least {settings.MinimumPasswordLength} characters."];

        // The ceiling is not a strength rule. HMAC reduces anything past its block size to a fixed
        // width before the iterations start, so the extra characters buy nothing - while an
        // unbounded field on an anonymous endpoint is a way to spend the server's memory and CPU.
        if (password.Length > settings.MaximumPasswordLength)
            return [$"Use at most {settings.MaximumPasswordLength} characters."];

        return [];
    }
}
