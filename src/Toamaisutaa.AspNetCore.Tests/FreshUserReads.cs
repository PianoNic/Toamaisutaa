using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An <see cref="IUserStore"/> that reads every user afresh, as a store without EF's identity map
/// does. EF hands a request back the row it read first, which hides any code that reads a stamp
/// twice and only ever compares the first copy.
/// </summary>
internal static class FreshUserReads
{
    internal static void Register(IServiceCollection services)
    {
        var real = services.Last(descriptor => descriptor.ServiceType == typeof(IUserStore)).ImplementationFactory!;

        services.AddScoped<IUserStore>(provider =>
            new Store((IUserStore)real(provider), provider.GetRequiredService<IServiceScopeFactory>(), real));
    }

    private sealed class Store(IUserStore inner, IServiceScopeFactory scopes, Func<IServiceProvider, object> real) : IUserStore
    {
        public async Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            await using var scope = scopes.CreateAsyncScope();
            return await ((IUserStore)real(scope.ServiceProvider)).FindByIdAsync(id, cancellationToken);
        }

        public Task<string?> ReadSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.ReadSecurityStampAsync(userId, cancellationToken);

        public Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            inner.FindByEmailAsync(email, cancellationToken);

        public Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(profile, cancellationToken);

        public Task<ToamaisutaaUser> CreateAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(user, cancellationToken);

        public Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default) =>
            inner.UpdateProfileAsync(user, profile, cancellationToken);

        public Task UpdateSecurityStampAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default) =>
            inner.UpdateSecurityStampAsync(userId, securityStamp, cancellationToken);

        public Task SetUserNameAsync(Guid userId, string userName, CancellationToken cancellationToken = default) =>
            inner.SetUserNameAsync(userId, userName, cancellationToken);

        public Task SetEmailAsync(Guid userId, string email, CancellationToken cancellationToken = default) =>
            inner.SetEmailAsync(userId, email, cancellationToken);

        public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(userId, cancellationToken);
    }
}
