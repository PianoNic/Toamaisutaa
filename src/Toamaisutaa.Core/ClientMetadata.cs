using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// What a session row and a trusted-device row keep about the caller that established them.
/// </summary>
/// <remarks>
/// Shared rather than written twice: both answer the same question in a list somebody reads before
/// revoking something, and two copies of the address truncation would be two chances to store a
/// full address after configuration asked for a truncated one.
/// </remarks>
internal static class ClientMetadata
{
    /// <summary>What the <c>UserAgent</c> columns are sized for.</summary>
    internal const int UserAgentLength = 256;

    /// <summary>
    /// Everything a request says about where it came from, already truncated and already filtered
    /// through <see cref="IpAddressStorage"/> - so a value carried from an existing row can be
    /// passed on unchanged rather than resolved a second time. Resolving a stored address again
    /// would hand <c>ResolveAddress</c> a string like <c>192.0.2.0/24</c>, which does not parse,
    /// and the column would quietly empty itself on the first rotation.
    /// </summary>
    internal readonly record struct SessionClient(string? UserAgent, string? IpAddress);

    internal static SessionClient Describe(string? userAgent, string? ipAddress, IpAddressStorage storage) =>
        new(Truncate(userAgent, UserAgentLength), ResolveAddress(ipAddress, storage));

    internal static string? Truncate(string? value, int length) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= length ? value : value[..length];

    /// <summary>
    /// Truncation keeps the network and drops the host: /24 for IPv4, /48 for IPv6. Enough to say
    /// "somewhere else" without storing something that identifies a person.
    /// </summary>
    internal static string? ResolveAddress(string? address, IpAddressStorage storage)
    {
        if (storage == IpAddressStorage.None || string.IsNullOrWhiteSpace(address))
            return null;

        if (storage == IpAddressStorage.Full)
            return Truncate(address, 64);

        if (!System.Net.IPAddress.TryParse(address, out var parsed))
            return null;

        var bytes = parsed.GetAddressBytes();

        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            bytes[3] = 0;
            return new System.Net.IPAddress(bytes).ToString() + "/24";
        }

        for (var i = 6; i < bytes.Length; i++)
            bytes[i] = 0;

        return new System.Net.IPAddress(bytes).ToString() + "/48";
    }
}
