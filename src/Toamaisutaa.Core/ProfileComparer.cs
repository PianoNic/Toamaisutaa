using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>Whether a mapped profile says anything the stored row does not. This is what makes
/// <see cref="ProfileSyncMode.OnChange"/> mean something.</summary>
internal static class ProfileComparer
{
    internal static bool HasChanges(ToamaisutaaUser user, ExternalUserProfile profile) =>
        !Same(user.UserName, profile.UserName)
        || !Same(user.Email, profile.Email)
        || !Same(user.DisplayName, profile.DisplayName)
        || !Same(user.PictureUrl, profile.PictureUrl);

    /// <summary>Blank and absent are the same thing, so a claim that arrives empty does not count
    /// as a change against a stored null.</summary>
    private static bool Same(string? stored, string? mapped) =>
        string.Equals(Normalise(stored), Normalise(mapped), StringComparison.Ordinal);

    private static string? Normalise(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
