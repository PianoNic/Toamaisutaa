using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.PasswordValidation.Hibp.Tests;

/// <summary>
/// That the check is added to the password rules rather than put in their place, whichever order
/// the two registrations happen in.
/// </summary>
/// <remarks>
/// <c>AddToamaisutaaPasswordLogin</c> lives in Toamaisutaa.AspNetCore, which this package does not
/// reference, so the two orders are reproduced here with the one registration out of it that
/// matters: a <c>TryAddSingleton</c> of the length rules.
/// </remarks>
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

    // The other order has to work too, and it does for a reason worth pinning down:
    // AddToamaisutaaPasswordLogin registers its validator with TryAdd, so it finds this one already
    // standing and leaves it alone.
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

    // Somebody who registered their own validator gets the breach check on top of theirs, not on
    // top of the length rules they deliberately replaced.
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

    // Leaving the wrapped registration in the container would hand anybody resolving
    // IPasswordValidator a coin flip over which of the two they get.
    [Test]
    public async Task LeavesExactlyOneValidatorRegistered()
    {
        var services = Services();
        AddPasswordLoginsValidator(services);
        services.AddToamaisutaaHibpPasswordValidation(_ => { });

        await Assert.That(services.Count(descriptor => descriptor.ServiceType == typeof(IPasswordValidator))).IsEqualTo(1);
    }

    [Test]
    public async Task RegistersTheRangeApiAsTheCorpus()
    {
        var services = Services();
        services.AddToamaisutaaHibpPasswordValidation(_ => { });

        await Assert.That(services.BuildServiceProvider().GetRequiredService<IBreachedPasswordIndex>())
            .IsTypeOf<PwnedPasswordsRangeIndex>();
    }

    // Two assertions, not one. Registering no startup check at all makes the second pass on its own:
    // Single() over an empty sequence throws the very InvalidOperationException the assertion is
    // waiting for, and the test goes green for a container with nothing in it.
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
