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
    /// <remarks>
    /// Called from <c>POST /auth/password/forgot</c> after the 204 has gone, on a background queue,
    /// in a scope of its own. There is no <c>HttpContext</c>: build links from configuration, never
    /// from the request's host. What this throws is logged and reaches nobody, because the caller
    /// was answered before it ran.
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default);
}
