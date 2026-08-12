namespace Toamaisutaa.Abstractions;

/// <summary>Everything read from the <c>TrustedDevices</c> configuration section.</summary>
public sealed class ToamaisutaaTrustedDeviceOptions
{
    /// <summary>
    /// Absolute, measured from when the device was first trusted. Rotation does not extend it, so a
    /// device signed in from every week still has to complete a live challenge eventually.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Zero means unlimited. Above the cap the oldest family is revoked, because every live device
    /// is a second factor somebody is not being asked for and an unbounded list of them accumulates
    /// one per browser, forever.
    /// </summary>
    public int MaxDevicesPerUser { get; set; } = 10;

    public IpAddressStorage IpAddressStorage { get; set; } = IpAddressStorage.None;

    /// <summary>
    /// Composed onto <see cref="ToamaisutaaLocalLoginOptions.EndpointPrefix"/>, the same way the
    /// two-factor endpoints append <c>/2fa</c>. A relative suffix rather than a full path, so that
    /// moving local login moves these with it instead of stranding them at the old prefix.
    /// </summary>
    public string EndpointPrefix { get; set; } = "/devices";
}

/// <summary>
/// How much of the caller's address to keep against a trusted device.
/// </summary>
/// <remarks>
/// Three positions rather than a switch, because the switch is a false choice between storing
/// nothing and storing a precise personal identifier in a table a consumer's privacy notice may not
/// mention. <see cref="Truncated"/> answers "is this a different network" without answering "which
/// person".
/// </remarks>
public enum IpAddressStorage
{
    /// <summary>The default. The column stays null.</summary>
    None,

    /// <summary>IPv4 to /24, IPv6 to /48.</summary>
    Truncated,

    Full,
}
