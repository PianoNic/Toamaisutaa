namespace Toamaisutaa.Abstractions;

/// <summary>Everything read from the <c>TrustedDevices</c> configuration section.</summary>
public sealed class ToamaisutaaTrustedDeviceOptions
{
    /// <summary>
    /// Absolute, measured from when the device was first trusted. Rotation does not extend it.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Zero means unlimited. Above the cap the oldest family is revoked.
    /// </summary>
    public int MaxDevicesPerUser { get; set; } = 10;

    public IpAddressStorage IpAddressStorage { get; set; } = IpAddressStorage.None;

    /// <summary>
    /// A suffix composed onto <see cref="ToamaisutaaLocalLoginOptions.EndpointPrefix"/>, so moving
    /// local login moves these endpoints with it.
    /// </summary>
    public string EndpointPrefix { get; set; } = "/devices";
}

/// <summary>
/// How much of the caller's address to keep against a trusted device.
/// </summary>
/// <remarks>
/// <see cref="Truncated"/> tells networks apart without storing a precise personal identifier.
/// </remarks>
public enum IpAddressStorage
{
    /// <summary>The default. The column stays null.</summary>
    None,

    /// <summary>IPv4 to /24, IPv6 to /48.</summary>
    Truncated,

    Full,
}
