namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a reset token to the person who asked for it. No implementation ships; registration is
/// required before password login will start.
/// </summary>
public interface IPasswordResetNotifier
{
    /// <summary>
    /// Called with the raw token, the only moment it exists in the clear. Put it in a link your own
    /// reset page understands.
    /// </summary>
    /// <remarks>
    /// Runs on a background queue after the 204 has gone, in its own scope. There is no
    /// <c>HttpContext</c>: build links from configuration, never from the request's host. Exceptions
    /// are logged only.
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string resetToken, CancellationToken cancellationToken = default);
}
