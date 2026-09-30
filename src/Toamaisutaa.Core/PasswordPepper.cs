using System.Security.Cryptography;
using System.Text;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Shared by every hasher because a copy of this rule that drifts either accepts a password against
/// a hash never made from it or locks a fleet out.
/// </summary>
internal static class PasswordPepper
{
    internal static string? ActiveVersion(ToamaisutaaLocalLoginOptions settings) =>
        string.IsNullOrWhiteSpace(settings.Pepper) ? null : settings.PepperVersion;

    internal static byte[]? Active(ToamaisutaaLocalLoginOptions settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Pepper))
            return null;

        return Convert.FromBase64String(settings.Pepper);
    }

    /// <summary>
    /// False means the key is not held and the caller must fail closed; verifying the row as
    /// unpeppered would accept the bare password against a hash never made from it.
    /// </summary>
    internal static bool TryResolve(ToamaisutaaLocalLoginOptions settings, string? version, out byte[]? pepper)
    {
        pepper = null;

        if (version is null)
            return true;

        // Without an active pepper, an empty active slot would shadow the same version in
        // RetiredPeppers and every existing row would stop verifying after the pepper is removed.
        var hasActivePepper = !string.IsNullOrWhiteSpace(settings.Pepper);

        var encoded = hasActivePepper && string.Equals(version, settings.PepperVersion, StringComparison.Ordinal)
            ? settings.Pepper
            : settings.RetiredPeppers.TryGetValue(version, out var retired) ? retired : null;

        if (string.IsNullOrWhiteSpace(encoded))
            return false;

        try
        {
            pepper = Convert.FromBase64String(encoded);
            return pepper.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static byte[] Preprocess(string password, byte[]? pepper)
    {
        var bytes = Encoding.UTF8.GetBytes(password);

        return pepper is null ? bytes : HMACSHA256.HashData(pepper, bytes);
    }
}
