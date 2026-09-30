namespace Toamaisutaa.Abstractions;

/// <summary>
/// Delivers a magic-link token to the verified address of the account that asked for one. The
/// package ships no implementation.
/// </summary>
/// <remarks>
/// <para>
/// Optional. Registering one is what maps <c>POST /auth/magic-link</c> and
/// <c>POST /auth/magic-link/verify</c>.
/// </para>
/// <para>
/// The mail this sends is a credential exchanged directly for a token pair, so treat it as a
/// password: one recipient, no logging, no forwarding rules.
/// </para>
/// </remarks>
public interface IMagicLinkNotifier
{
    /// <summary>
    /// Called with the raw token, the only moment it exists in the clear. Put it in a link your own
    /// sign-in page understands.
    /// </summary>
    /// <remarks>
    /// Send it to <see cref="ToamaisutaaUser.Email"/> on the <paramref name="user"/> passed here, the
    /// verified credential address, and never re-read the user: the profile's address is written by
    /// an identity provider's sync.
    /// <para>
    /// Runs on a background queue after the 204, with no <c>HttpContext</c>: build links from
    /// configuration, never from the request's host. What this throws is logged and reaches nobody.
    /// </para>
    /// </remarks>
    Task SendAsync(ToamaisutaaUser user, string magicLinkToken, CancellationToken cancellationToken = default);
}
