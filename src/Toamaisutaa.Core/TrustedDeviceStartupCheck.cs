using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Refuses to start rather than failing at the first sign-in. Everything here is invisible until
/// somebody tries to be remembered, which is the worst moment to find out.
/// </summary>
internal sealed class TrustedDeviceStartupCheck(
    IServiceCollection services,
    IOptions<ToamaisutaaTrustedDeviceOptions> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var problems = new List<string>();

        if (!IsRegistered(typeof(ITwoFactorService)))
        {
            problems.Add(
                "AddToamaisutaaTrustedDevices() is registered but AddToamaisutaaTwoFactor() is not. A trusted device is a "
                + "cached second factor, so without two-factor authentication there is nothing for it to cache and no "
                + "challenge for it to skip. Add AddToamaisutaaTwoFactor(configuration), or remove this call.");
        }

        if (!IsRegistered(typeof(IPasswordSignInService)))
        {
            problems.Add(
                "AddToamaisutaaTrustedDevices() is registered but AddToamaisutaaPasswordLogin() is not. Device trust is "
                + "redeemed during a local sign-in; an identity provider owns its own sign-ins and this package never "
                + "sees them. Add AddToamaisutaaPasswordLogin(configuration), or remove this call.");
        }

        if (!IsRegistered(typeof(ITrustedDeviceStore)))
        {
            problems.Add(
                $"No {nameof(ITrustedDeviceStore)} is registered. Call AddToamaisutaaEntityFrameworkStores<TContext>() or "
                + "AddToamaisutaaDbContext(...), or register the store yourself.");
        }

        if (settings.Lifetime <= TimeSpan.Zero)
            problems.Add("TrustedDevices:Lifetime must be positive, or no device could ever be trusted.");

        if (settings.MaxDevicesPerUser < 0)
            problems.Add($"TrustedDevices:MaxDevicesPerUser is {settings.MaxDevicesPerUser}; use 0 for unlimited.");

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Toamaisutaa trusted devices are registered but not usable:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, problems.Select(problem => "  - " + problem)));
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private bool IsRegistered(Type serviceType)
    {
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == serviceType)
                return true;
        }

        return false;
    }
}
