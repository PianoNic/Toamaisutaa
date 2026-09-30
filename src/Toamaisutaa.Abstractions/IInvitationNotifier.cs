namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers an invitation token to the person meant to complete it. The package ships no
/// implementation.
/// </summary>
/// <remarks>
/// Optional. Registering one is what maps <c>POST /auth/invitations</c> and
/// <c>POST /auth/invitations/complete</c>.
/// </remarks>
public interface IInvitationNotifier
{
    /// <summary>
    /// Called with the raw token, the only moment it exists in the clear. Put it in a link your own
    /// registration-completion page understands.
    /// </summary>
    Task SendAsync(ToamaisutaaUser user, string invitationToken, CancellationToken cancellationToken = default);
}
