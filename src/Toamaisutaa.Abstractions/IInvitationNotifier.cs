namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers an invitation token to the person meant to complete it. The package ships no
/// implementation and no default, the same reasoning <see cref="IPasswordResetNotifier"/> follows:
/// sending mail is not an authentication library's job.
/// </summary>
/// <remarks>
/// Optional, unlike <see cref="IPasswordResetNotifier"/>. Registering one is what maps
/// <c>POST /auth/invitations</c> and <c>POST /auth/invitations/complete</c> at all - an application
/// that never reserves accounts for someone else does not need one to use local login.
/// </remarks>
public interface IInvitationNotifier
{
    /// <summary>
    /// Called with the raw token, which is the only moment it exists in the clear - the stored copy
    /// is a hash. Put it in a link your own registration-completion page understands.
    /// </summary>
    Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default);
}
