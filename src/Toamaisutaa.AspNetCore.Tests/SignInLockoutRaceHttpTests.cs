using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A right password among a wave of wrong ones, sent together. The wave locks the account while the
/// right one is still being hashed, and the right one used to sign in regardless - clearing the lock
/// the wave had just set on its way out.
/// </summary>
public class SignInLockoutRaceHttpTests
{
    [Test]
    public async Task A_right_password_hashed_while_the_account_locks_is_refused_and_leaves_the_lock()
    {
        var hasher = new HeldHasher();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<IPasswordHasher>(provider =>
                hasher.Wrap(new Pbkdf2PasswordHasher(provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>()))));

        var account = await Account.RegisterAsync(app);
        hasher.Hold = account.Password;

        var right = app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        for (var i = 0; i < 5; i++)
            await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });

        hasher.Hold = null;
        hasher.Release.Set();

        await Assert.That((await right).StatusCode).IsNotEqualTo(HttpStatusCode.OK);

        var afterwards = await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = account.Password });
        await Assert.That(afterwards.StatusCode).IsNotEqualTo(HttpStatusCode.OK);
    }

    /// <summary>Stops the one verification of <see cref="Hold"/> until the test lets it go, which is
    /// the window a real wave has while a hash is being derived.</summary>
    private sealed class HeldHasher : IPasswordHasher
    {
        private IPasswordHasher _inner = null!;

        internal volatile string? Hold;

        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal ManualResetEventSlim Release { get; } = new();

        internal IPasswordHasher Wrap(IPasswordHasher inner)
        {
            _inner = inner;
            return this;
        }

        public string Hash(string password) => _inner.Hash(password);

        public PasswordVerificationResult Verify(string password, string hash)
        {
            if (password == Hold)
            {
                Entered.TrySetResult();
                Release.Wait(TimeSpan.FromSeconds(30));
            }

            return _inner.Verify(password, hash);
        }
    }
}
