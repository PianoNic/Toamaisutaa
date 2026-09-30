namespace Toamaisutaa.Abstractions;

/// <summary>
/// Receives every security-relevant outcome this package reaches, so an application can write an
/// audit table instead of scraping its logs for one.
/// </summary>
/// <remarks>
/// <para>
/// Optional. Every registered sink is called, in registration order.
/// </para>
/// <para>
/// A sink runs inside the request and its exceptions are logged and absorbed, never retried, so a
/// sink that must not lose an event should write it somewhere durable itself.
/// </para>
/// <para>
/// Nothing handed here is a credential.
/// </para>
/// </remarks>
public interface IAuthenticationEventSink
{
    Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default);
}
