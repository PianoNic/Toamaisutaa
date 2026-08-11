using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;
using Toamaisutaa.EntityFrameworkCore;

namespace Microsoft.Extensions.DependencyInjection;

public static class ToamaisutaaEntityFrameworkServiceCollectionExtensions
{
    /// <summary>
    /// Backs provisioning with a <c>DbContext</c> you already have. Apply
    /// <c>ApplyToamaisutaaConfiguration()</c> in its <c>OnModelCreating</c> and generate the
    /// migration in your own project.
    /// </summary>
    public static IServiceCollection AddToamaisutaaEntityFrameworkStores<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<EntityFrameworkStore<TContext>>();
        services.TryAddScoped<IUserStore>(provider => provider.GetRequiredService<EntityFrameworkStore<TContext>>());
        services.TryAddScoped<IExternalLoginStore>(provider => provider.GetRequiredService<EntityFrameworkStore<TContext>>());

        // Registered whether or not password login is switched on: having the stores available
        // enables nothing by itself, and the alternative is a second registration call that exists
        // only to be forgotten.
        services.TryAddScoped<EntityFrameworkPasswordStore<TContext>>();
        services.TryAddScoped<IPasswordCredentialStore>(provider => provider.GetRequiredService<EntityFrameworkPasswordStore<TContext>>());
        services.TryAddScoped<IRefreshTokenStore>(provider => provider.GetRequiredService<EntityFrameworkPasswordStore<TContext>>());
        services.TryAddScoped<IPasswordResetTokenStore>(provider => provider.GetRequiredService<EntityFrameworkPasswordStore<TContext>>());

        services.TryAddScoped<EntityFrameworkTwoFactorStore<TContext>>();
        services.TryAddScoped<ITwoFactorStore>(provider => provider.GetRequiredService<EntityFrameworkTwoFactorStore<TContext>>());
        services.TryAddScoped<IRecoveryCodeStore>(provider => provider.GetRequiredService<EntityFrameworkTwoFactorStore<TContext>>());
        services.TryAddScoped<ITwoFactorChallengeStore>(provider => provider.GetRequiredService<EntityFrameworkTwoFactorStore<TContext>>());

        return services;
    }

    /// <summary>
    /// Backs provisioning with the package's own context, so the tables live apart from yours.
    /// The provider and its migrations assembly are yours to name:
    /// <code>
    /// services.AddToamaisutaaDbContext(db => db.UseNpgsql(connectionString,
    ///     npgsql => npgsql.MigrationsAssembly("Toamaisutaa.EntityFrameworkCore.Migrations.Postgres")));
    /// </code>
    /// </summary>
    public static IServiceCollection AddToamaisutaaDbContext(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddDbContext<ToamaisutaaDbContext>(configure);

        return services.AddToamaisutaaEntityFrameworkStores<ToamaisutaaDbContext>();
    }
}
