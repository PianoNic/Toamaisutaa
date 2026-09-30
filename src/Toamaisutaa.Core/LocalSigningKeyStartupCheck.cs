using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// For validate-only processes, where nothing else reads <see cref="LocalSigningKeyRing.Problems"/>
/// and a mangled key would pass startup and 401 every token. Stands down when password login is
/// registered, since <see cref="PasswordLoginStartupCheck"/> reports it there.
/// </summary>
internal sealed class LocalSigningKeyStartupCheck(IServiceCollection services, LocalSigningKeyRing signingKeys)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (signingKeys.Problems.Count == 0 || PasswordLoginIsRegistered())
            return Task.CompletedTask;

        throw StartupProblems.Refusal("Toamaisutaa cannot use LocalLogin:SigningKeys as configured:", signingKeys.Problems);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private bool PasswordLoginIsRegistered()
    {
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == typeof(IPasswordSignInService))
                return true;
        }

        return false;
    }
}
