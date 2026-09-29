using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The real hasher, except that hashing or verifying <see cref="Hold"/> stops until the test lets
/// it go. A key derivation is the window a real race has, and this pins another request inside it.
/// </summary>
internal sealed class HeldHasher : IPasswordHasher
{
    private readonly ManualResetEventSlim _release = new();
    private IPasswordHasher _inner = null!;

    internal volatile string? Hold;

    /// <summary>Completes once a request is being held.</summary>
    internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal void Register(IServiceCollection services) =>
        services.AddSingleton<IPasswordHasher>(provider =>
        {
            _inner = new Pbkdf2PasswordHasher(provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>());
            return this;
        });

    /// <summary>Stops holding and lets the held request go on.</summary>
    internal void Let()
    {
        Hold = null;
        _release.Set();
    }

    public string Hash(string password)
    {
        Wait(password);
        return _inner.Hash(password);
    }

    public PasswordVerificationResult Verify(string password, string hash)
    {
        Wait(password);
        return _inner.Verify(password, hash);
    }

    private void Wait(string password)
    {
        if (password != Hold)
            return;

        Entered.TrySetResult();
        _release.Wait(TimeSpan.FromSeconds(30));
    }
}
