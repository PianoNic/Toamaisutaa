namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a verification token to the address it is meant to prove. The package ships no
/// implementation and no default, the same reasoning <see cref="IPasswordResetNotifier"/> follows:
/// sending mail is not an authentication library's job.
/// </summary>
/// <remarks>
/// Optional, unlike <see cref="IPasswordResetNotifier"/>. Registering one is what maps
/// <c>POST /auth/email</c> and <c>POST /auth/email/verify</c> at all - an application that never
/// verifies an address does not need one to use local login.
/// </remarks>
public interface IEmailVerificationNotifier
{
    /// <summary>
    /// Called with the raw token, which is the only moment it exists in the clear - the stored copy
    /// is a hash. Put it in a link your own verification page understands.
    /// </summary>
    /// <remarks>
    /// Send it to <c>email</c>, not to <see cref="ToamaisutaaUser.Email"/>. Those two differ for
    /// every change of address, and mailing the link to the one already on the account would prove
    /// control of the wrong mailbox.
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string email, string verificationToken, CancellationToken cancellationToken = default);
}
