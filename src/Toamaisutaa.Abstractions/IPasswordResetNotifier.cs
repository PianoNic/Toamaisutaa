namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a reset token to the person who asked for it. The package ships no implementation and
/// no default: sending mail is not an authentication library's job, and every application already
/// has an opinion about how it does it. Registration is required before password login will start.
/// </summary>
public interface IPasswordResetNotifier
{
    /// <summary>
    /// Called with the raw token, which is the only moment it exists in the clear - the stored copy
    /// is a hash. Put it in a link your own reset page understands.
    /// </summary>
    Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default);
}
