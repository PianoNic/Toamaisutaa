namespace Toamaisutaa.Abstractions;

/// <summary>
/// Receives every security-relevant outcome this package reaches, so an application can write an
/// audit table instead of scraping its logs for one.
/// </summary>
/// <remarks>
/// <para>
/// Optional, and there is no default: with none registered nothing is published and the sign-in
/// path behaves exactly as it did before. Register as many as you like - all of them are called,
/// in registration order.
/// </para>
/// <para>
/// A sink runs inside the request that caused the event and its failures are absorbed: an exception
/// is logged and the request carries on. Auditing that turns a good sign-in into a 500 is worse
/// than no auditing, so a sink that must not lose an event should write it somewhere durable
/// itself - a row, a queue - rather than rely on this call to be retried, because it is not.
/// </para>
/// <para>
/// Nothing handed here is a credential. Events carry the user id, the <c>amr</c> values and the
/// time; never a password, a TOTP secret, a recovery code, a reset or invitation token, or a
/// refresh token.
/// </para>
/// </remarks>
public interface IAuthenticationEventSink
{
    Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default);
}
