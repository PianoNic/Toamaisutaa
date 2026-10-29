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

    /// <summary>
    /// The same, with what the message has to warn about. Implement it: the default drops the context
    /// and sends the ordinary message.
    /// </summary>
    /// <remarks>
    /// With <see cref="EmailVerificationContext.TakesFromAnotherAccount"/> the address is currently on
    /// another account, unproven, and redeeming the link moves it away from there. Somebody reading an
    /// ordinary "confirm your address" mail for an address they already use would click it, and hand
    /// it to whoever asked.
    /// </remarks>
    Task SendAsync(
        ToamaisutaaUser user,
        string email,
        string verificationToken,
        EmailVerificationContext context,
        CancellationToken cancellationToken = default) =>
        SendAsync(user, email, verificationToken, cancellationToken);

    /// <summary>
    /// Somebody asked to use <paramref name="email"/>, which another account has already proven, so no
    /// link was issued. The caller is told the same as when one is, so it cannot learn which addresses
    /// have accounts; this tells the address's owner instead. The default sends nothing.
    /// </summary>
    Task SendAddressInUseAsync(ToamaisutaaUser requester, string email, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    /// <summary>
    /// Sends the six-digit code that confirms <paramref name="email"/> when
    /// <see cref="ToamaisutaaLocalLoginOptions.RequireVerifiedEmailForSignIn"/> holds a sign-in back.
    /// Called with the raw code, the only moment it exists in the clear; never log it.
    /// </summary>
    /// <remarks>
    /// The default throws, and startup refuses the option with a notifier that does not implement this,
    /// unless an <see cref="IEmailVerificationMethod"/> of your own replaces the code.
    /// <paramref name="validFor"/> is <see cref="ToamaisutaaLocalLoginOptions.EmailVerificationCodeLifetime"/>,
    /// for a message that says how long the code lasts.
    /// </remarks>
    Task SendCodeAsync(ToamaisutaaUser user, string email, string code, TimeSpan validFor, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            $"{GetType().Name} does not implement {nameof(IEmailVerificationNotifier)}.{nameof(SendCodeAsync)}, which "
            + "LocalLogin:RequireVerifiedEmailForSignIn needs to mail a verification code.");
}

public sealed record EmailVerificationContext
{
    /// <summary>The address is held, unverified, by another account, which loses it if the link is used.</summary>
    public bool TakesFromAnotherAccount { get; init; }
}
