using System.Net;
using System.Net.Sockets;

namespace Toamaisutaa.Core;

internal static class Nat64Prefix
{
    /// <summary>The prefix lengths RFC 6052 defines an embedding for.</summary>
    private static readonly int[] Lengths = [32, 40, 48, 56, 64, 96];

    internal static bool TryParse(string value, out IPNetwork prefix) =>
        IPNetwork.TryParse(value, out prefix)
        && prefix.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6
        && Lengths.Contains(prefix.PrefixLength);
}
