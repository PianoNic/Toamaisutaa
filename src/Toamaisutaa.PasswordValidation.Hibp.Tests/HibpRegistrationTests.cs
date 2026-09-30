using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

/// <summary>
/// <c>AddToamaisutaaPasswordLogin</c> is not referenced here, so its one relevant registration, a
/// <c>TryAddSingleton</c> of the length rules, stands in for it.
/// </summary>
public class HibpRegistrationTests
{
    private static IServiceCollection Services()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<ToamaisutaaLocalLoginOptions>();
        return services;
    }

    private static void AddPasswordLoginsValidator(IServiceCollection services) =>
        services.TryAddSingleton<IPasswordValidator, DefaultPasswordValidator>();

    private static IPasswordValidator Resolve(IServiceCollection services) =>
        services.BuildServiceProvider().GetRequiredService<IPasswordValidator>();

    private static IServiceCollection ServicesWithAScopedValidator(DisposalLog log)
    {
        var services = Services();
        services.AddSingleton(log);
        services.AddScoped<ScopedDependency>();
        services.AddScoped<IPasswordValidator, ScopedInnerValidator>();
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 0));

        return services;
    }

    private static ScopedDependency Dependency(IServiceScope scope) =>
        scope.ServiceProvider.GetRequiredService<ScopedDependency>();

    private static async Task<IReadOnlyList<string>> Errors(IServiceScope scope) =>
        await scope.ServiceProvider.GetRequiredService<IPasswordValidator>()
            .ValidateAsync("a password long enough to pass");

    [Test]
    public async Task WrapsTheLengthRulesWhenAddedAfterThem()
    {
        var services = Services();
        AddPasswordLoginsValidator(services);
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 0));

        var validator = Resolve(services);

        await Assert.That(validator).IsTypeOf<HibpPasswordValidator>();
        await Assert.That(await validator.ValidateAsync("short")).IsNotEmpty();
    }

    [Test]
    public async Task WrapsTheLengthRulesWhenAddedBeforeThem()
    {
        var services = Services();
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        AddPasswordLoginsValidator(services);
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 0));

        var validator = Resolve(services);

        await Assert.That(validator).IsTypeOf<HibpPasswordValidator>();
        await Assert.That(await validator.ValidateAsync("short")).IsNotEmpty();
    }

    [Test]
    public async Task AddsTheBreachCheckToTheLengthRulesRatherThanReplacingThem()
    {
        var services = Services();
        AddPasswordLoginsValidator(services);
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 500));

        await Assert.That(await Resolve(services).ValidateAsync("a password long enough to pass")).IsNotEmpty();
    }

    [Test]
    public async Task WrapsAValidatorOfYourOwnRatherThanTheDefault()
    {
        var services = Services();
        var mine = new FakeInnerValidator("Ask the gate master first.");
        services.AddSingleton<IPasswordValidator>(mine);
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 0));

        var errors = await Resolve(services).ValidateAsync("a password long enough to pass");

        await Assert.That(errors).IsEquivalentTo(new[] { "Ask the gate master first." });
        await Assert.That(mine.Seen).HasSingleItem();
    }

    [Test]
    public async Task LeavesExactlyOneValidatorRegistered()
    {
        var services = Services();
        AddPasswordLoginsValidator(services);
        services.AddToamaisutaaHibpPasswordValidation(_ => { });
        services.AddSingleton<IBreachedPasswordIndex>(new FakeBreachedPasswordIndex(count: 0));

        await Assert.That(services.Count(descriptor =>
            descriptor.ServiceType == typeof(IPasswordValidator) && descriptor.ServiceKey is null)).IsEqualTo(1);

        await Assert.That(services.BuildServiceProvider().GetServices<IPasswordValidator>().ToList()).HasSingleItem();
    }

    [Test]
    public async Task KeepsAScopedValidatorOfYourOwnScoped()
    {
        var services = ServicesWithAScopedValidator(new DisposalLog());

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        await Assert.That(await Errors(first)).IsEquivalentTo(new[] { Dependency(first).Id });
        await Assert.That(await Errors(second)).IsEquivalentTo(new[] { Dependency(second).Id });
    }

    [Test]
    public async Task DisposesAScopedValidatorOfYourOwnWithItsScope()
    {
        var log = new DisposalLog();

        using var provider = ServicesWithAScopedValidator(log)
            .BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        string id;

        using (var scope = provider.CreateScope())
        {
            id = Dependency(scope).Id;
            await Errors(scope);

            await Assert.That(log.Disposed).IsEmpty();
        }

        await Assert.That(log.Disposed).IsEquivalentTo(new[] { id });
    }

    [Test]
    public async Task RegistersTheRangeApiAsTheCorpus()
    {
        var services = Services();
        services.AddToamaisutaaHibpPasswordValidation(_ => { });

        await Assert.That(services.BuildServiceProvider().GetRequiredService<IBreachedPasswordIndex>())
            .IsTypeOf<PwnedPasswordsRangeIndex>();
    }

    // Asserts the check exists first, or an empty container would pass by throwing the same
    // InvalidOperationException.
    [Test]
    public async Task RefusesToStartOnOptionsItCannotUse()
    {
        var services = Services();
        services.AddToamaisutaaHibpPasswordValidation(options => options.BreachThreshold = 0);

        var checks = services.BuildServiceProvider().GetServices<Microsoft.Extensions.Hosting.IHostedService>().ToList();

        await Assert.That(checks).HasSingleItem();
        await Assert.That(checks[0]).IsTypeOf<HibpStartupCheck>();
        await Assert.That(async () => await checks[0].StartAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
    }
}
