using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Refuses to start on a <c>LocalLogin:SigningKeys</c> entry the ring could not read, in the process
/// where nothing else would say so.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="PasswordLoginStartupCheck"/> already reports that list, next to every other
/// misconfiguration and in one message, so this stands down when password login is registered and
/// the lines are printed once.
/// </para>
/// <para>
/// What it is here for is the other shape: a process that issues no token and only validates the
/// ones another instance issued still reads the same key list. With no password login registered,
/// nothing read <see cref="LocalSigningKeyRing.Problems"/> at all - a mangled PEM dropped the entry,
/// the host started clean, and every token it was configured to accept came back 401, which is
/// exactly what an expired one looks like.
/// </para>
/// </remarks>
internal sealed class LocalSigningKeyStartupCheck(IServiceCollection services, LocalSigningKeyRing signingKeys)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (signingKeys.Problems.Count == 0 || PasswordLoginIsRegistered())
            return Task.CompletedTask;

        throw new InvalidOperationException(
            "Toamaisutaa cannot use LocalLogin:SigningKeys as configured:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, signingKeys.Problems.Select(problem => "  - " + problem)));
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Asked of the registrations rather than of the hosted services, because the sign-in service is
    /// what <c>AddToamaisutaaPasswordLogin</c> is, and it is registered by nothing else.
    /// </summary>
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
