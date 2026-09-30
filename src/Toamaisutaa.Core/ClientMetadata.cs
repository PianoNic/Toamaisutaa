using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

internal static class ClientMetadata
{
    internal const int UserAgentLength = 256;

    /// <summary>
    /// Already resolved, so a value carried from an existing row is passed on unchanged: resolving a
    /// stored <c>192.0.2.0/24</c> again does not parse and would empty the column on rotation.
    /// </summary>
    internal readonly record struct SessionClient(string? UserAgent, string? IpAddress);

    internal static SessionClient Describe(string? userAgent, string? ipAddress, IpAddressStorage storage) =>
        new(Truncate(userAgent, UserAgentLength), ResolveAddress(ipAddress, storage));

    internal static string? Truncate(string? value, int length) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= length ? value : value[..length];

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
