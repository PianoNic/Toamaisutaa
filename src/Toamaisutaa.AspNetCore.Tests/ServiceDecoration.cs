using Microsoft.Extensions.DependencyInjection;

namespace Toamaisutaa.AspNetCore.Tests;

internal static class ServiceDecoration
{
    /// <summary>
    /// Replaces the package's registration of <typeparamref name="T"/> with a scoped wrapper around
    /// what it would have built, so a test can hold or count one call and leave every other real.
    /// </summary>
    internal static void Decorate<T>(this IServiceCollection services, Func<T, T> wrap)
        where T : class
    {
        var real = services.Last(descriptor => descriptor.ServiceType == typeof(T));

        services.AddScoped(provider => wrap(real.ImplementationFactory is { } factory
            ? (T)factory(provider)
            : (T)ActivatorUtilities.CreateInstance(provider, real.ImplementationType!)));
    }
}
