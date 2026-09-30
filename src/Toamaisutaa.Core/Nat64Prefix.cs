using System.Net;
using System.Net.Sockets;

namespace Toamaisutaa.Core;

/// <summary>What counts as a NAT64 prefix an IPv4 address can be read back out of.</summary>
internal static class Nat64Prefix
{
    /// <summary>The prefix lengths RFC 6052 defines an embedding for.</summary>
    private static readonly int[] Lengths = [32, 40, 48, 56, 64, 96];

    internal static bool TryParse(string value, out IPNetwork prefix) =>
        IPNetwork.TryParse(value, out prefix)
        && prefix.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6
        && Lengths.Contains(prefix.PrefixLength);
}
