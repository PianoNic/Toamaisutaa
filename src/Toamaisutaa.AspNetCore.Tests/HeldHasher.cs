using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>A key derivation is the window a real race has, so holding it pins another request inside it.</summary>
internal sealed class HeldHasher : IPasswordHasher
{
    private readonly ManualResetEventSlim _release = new();
    private IPasswordHasher _inner = null!;

    internal volatile string? Hold;

    /// <summary>Holds only when <see cref="Hold"/> is hashed - a rehash - and lets its
    /// verification through.</summary>
    internal volatile bool HashingOnly;

    internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal void Register(IServiceCollection services) =>
        services.AddSingleton<IPasswordHasher>(provider =>
        {
            _inner = new Pbkdf2PasswordHasher(provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>());
            return this;
        });

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
        if (!HashingOnly)
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
