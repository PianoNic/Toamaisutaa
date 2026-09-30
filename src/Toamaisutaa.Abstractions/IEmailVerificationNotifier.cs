namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a verification token to the address it is meant to prove. The package ships no
/// implementation.
/// </summary>
/// <remarks>
/// Optional. Registering one is what maps <c>POST /auth/email</c> and
/// <c>POST /auth/email/verify</c>.
/// </remarks>
public interface IEmailVerificationNotifier
{
    /// <summary>
    /// Called with the raw token, the only moment it exists in the clear. Put it in a link your own
    /// verification page understands.
    /// </summary>
    /// <remarks>
    /// Send it to <c>email</c>, not to <see cref="ToamaisutaaUser.Email"/>, or a change of address
    /// proves control of the wrong mailbox.
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default);
}
