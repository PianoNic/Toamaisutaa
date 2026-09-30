using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal static class ProfileComparer
{
    internal static bool HasChanges(ToamaisutaaUser user, ExternalUserProfile profile) =>
        !Same(user.UserName, profile.UserName)
        || !Same(user.Email, profile.Email)
        || !Same(user.DisplayName, profile.DisplayName)
        || !Same(user.PictureUrl, profile.PictureUrl);

    private static bool Same(string? stored, string? mapped) =>
        string.Equals(Normalise(stored), Normalise(mapped), StringComparison.Ordinal);

    private static string? Normalise(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
