using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Provisioning without stores resolves fine and then fails on the first authenticated request,
/// which is the worst time to find out. Fail at startup instead, naming the call that is missing.
/// The check runs against the registrations rather than resolving the services, because the stores
/// are scoped and the root provider cannot hand those out.
/// </summary>
internal sealed class ProvisioningStartupCheck(IServiceCollection services) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var missing = new List<string>();

        if (!IsRegistered(typeof(IUserStore)))
            missing.Add(nameof(IUserStore));

        if (!IsRegistered(typeof(IExternalLoginStore)))
            missing.Add(nameof(IExternalLoginStore));

        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"AddToamaisutaaProvisioning() was called but {string.Join(" and ", missing)} "
                + "is not registered, so provisioning has nowhere to write. Call "
                + "AddToamaisutaaEntityFrameworkStores<TContext>() or AddToamaisutaaDbContext(...), "
                + "or register the stores yourself.");
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
