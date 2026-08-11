using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>Everything wired with in-memory stores, so the flows can be exercised without a host.</summary>
internal sealed class PasswordHarness
{
    internal static readonly DateTimeOffset Start = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    private PasswordHarness(ToamaisutaaLocalLoginOptions options)
    {
        Clock = new FixedTimeProvider(Start);
        Options = options;

        var wrapped = Microsoft.Extensions.Options.Options.Create(options);

        Users = new FakeStore(Clock);
        Passwords = new FakePasswordStore();
        Issuer = new FakeAccessTokenIssuer(Clock);
        Notifier = new FakePasswordResetNotifier();
        Hasher = new Pbkdf2PasswordHasher(wrapped);

        SignIn = new PasswordSignInService(
            Passwords,
            Users,
            Passwords,
            Hasher,
            Issuer,
            new EmptyUserRoleProvider(),
            new DummyPasswordHash(Hasher),
            wrapped,
            Clock,
            NullLogger<PasswordSignInService>.Instance);

        Accounts = new PasswordAccountService(
            Passwords,
            Users,
            Passwords,
            Passwords,
            Hasher,
            new DefaultPasswordValidator(wrapped),
            Notifier,
            SignIn,
            wrapped,
            Clock,
            NullLogger<PasswordAccountService>.Instance);
    }

    internal FixedTimeProvider Clock { get; }

    internal ToamaisutaaLocalLoginOptions Options { get; }

    internal FakeStore Users { get; }

    internal FakePasswordStore Passwords { get; }

    internal FakeAccessTokenIssuer Issuer { get; }

    internal FakePasswordResetNotifier Notifier { get; }

    internal Pbkdf2PasswordHasher Hasher { get; }

    internal PasswordSignInService SignIn { get; }

    internal PasswordAccountService Accounts { get; }

    internal static PasswordHarness Create(Action<ToamaisutaaLocalLoginOptions>? configure = null)
    {
        // Iterations far below the production floor: these tests run many derivations and the floor
        // is a startup check, not a property of the hasher.
        var options = new ToamaisutaaLocalLoginOptions { Pbkdf2Iterations = 1_000 };
        configure?.Invoke(options);

        return new PasswordHarness(options);
    }

    /// <summary>A registered local account, as self-registration would have produced it.</summary>
    internal async Task<ToamaisutaaUser> RegisterAsync(string userName = "pianonic", string? email = "nic@example.com", string password = "correct horse battery")
    {
        var result = await Accounts.RegisterAsync(new RegisterRequest(userName, email, password));

        if (!result.Succeeded)
            throw new InvalidOperationException($"Registration failed: {string.Join("; ", result.Errors)}");

        return Users.Users.Single(user => user.Id == result.UserId);
    }

    /// <summary>An account as OIDC provisioning would have left it: a user row, an external login,
    /// and no password at all.</summary>
    internal ToamaisutaaUser ProvisionExternalUser(string email = "sso@example.com", string userName = "ssouser")
    {
        var user = new ToamaisutaaUser
        {
            Id = Guid.CreateVersion7(Clock.GetUtcNow()),
            UserName = userName,
            Email = email,
            DisplayName = "SSO Person",
            CreatedAt = Clock.GetUtcNow(),
            UpdatedAt = Clock.GetUtcNow(),
        };

        Users.Users.Add(user);
        return user;
    }
}
