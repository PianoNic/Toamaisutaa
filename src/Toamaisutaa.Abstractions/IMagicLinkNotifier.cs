namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a magic-link token to the verified address of the account that asked for one. The
/// package ships no implementation and no default, the same reasoning
/// <see cref="IPasswordResetNotifier"/> follows: sending mail is not an authentication library's
/// job.
/// </summary>
/// <remarks>
/// <para>
/// Optional, like <see cref="IEmailVerificationNotifier"/>. Registering one is what maps
/// <c>POST /auth/magic-link</c> and <c>POST /auth/magic-link/verify</c> at all - a deployment that
/// wants passwords and nothing else does not need one.
/// </para>
/// <para>
/// The mail this sends is the credential. A reset link asks for a new password before it hands
/// anything over; this one is exchanged for a token pair, so treat the message with the care a
/// password would get - one recipient, no logging, no forwarding rules.
/// </para>
/// </remarks>
public interface IMagicLinkNotifier
{
    /// <summary>
    /// Called with the raw token, which is the only moment it exists in the clear - the stored copy
    /// is a hash. Put it in a link your own sign-in page understands.
    /// </summary>
    /// <remarks>
    /// Send it to <see cref="ToamaisutaaUser.Email"/> and nowhere else. That address has been
    /// verified by the time this is called, which is the whole reason a link is allowed to be a
    /// credential at all.
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default);
}
