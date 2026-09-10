using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class TokenCleanupTests
{
    private static readonly DateTimeOffset Now = PasswordHarness.Start;

    [Test]
    public async Task SweepDeletesExpiredInvitationTokensAndLeavesLiveOnes()
    {
        var passwords = new FakePasswordStore();
        passwords.InvitationTokens.Add(Invitation("expired", Now.AddDays(-1)));
        passwords.InvitationTokens.Add(Invitation("live", Now.AddDays(7)));

        var services = new FakeServiceProvider()
            .Add<IRefreshTokenStore>(passwords)
            .Add<IPasswordResetTokenStore>(passwords)
            .Add<IInvitationTokenStore>(passwords);

        await SweepAsync(services);

        await Assert.That(passwords.InvitationTokens.Select(token => token.TokenHash)).IsEquivalentTo(["live"]);
    }

    [Test]
    public async Task SweepRunsWithNoInvitationStoreRegistered()
    {
        var passwords = new FakePasswordStore();
        passwords.ResetTokens.Add(new ToamaisutaaPasswordResetToken { TokenHash = "expired", ExpiresAt = Now.AddHours(-1) });

        var services = new FakeServiceProvider()
            .Add<IRefreshTokenStore>(passwords)
            .Add<IPasswordResetTokenStore>(passwords);

        await SweepAsync(services);

        await Assert.That(passwords.ResetTokens).IsEmpty();
    }

    [Test]
    public async Task SweepLogsTheInvitationCountWhenNothingElseExpired()
    {
        var passwords = new FakePasswordStore();
        passwords.InvitationTokens.Add(Invitation("expired", Now.AddDays(-1)));

        var services = new FakeServiceProvider()
            .Add<IRefreshTokenStore>(passwords)
            .Add<IPasswordResetTokenStore>(passwords)
            .Add<IInvitationTokenStore>(passwords);

        var logger = new CapturingLogger<TokenCleanupService>();

        await SweepAsync(services, logger);

        var line = logger.Entries.Single();
        await Assert.That(line.Level).IsEqualTo(LogLevel.Information);
        await Assert.That(line.Values["Invitations"]).IsEqualTo(1);
    }

    [Test]
    public async Task SweepDeletesExpiredMagicLinkTokensAndLeavesLiveOnes()
    {
        var passwords = new FakePasswordStore();
        passwords.MagicLinkTokens.Add(MagicLink("expired", Now.AddMinutes(-1)));
        passwords.MagicLinkTokens.Add(MagicLink("live", Now.AddMinutes(15)));

        var services = new FakeServiceProvider()
            .Add<IRefreshTokenStore>(passwords)
            .Add<IPasswordResetTokenStore>(passwords)
            .Add<IMagicLinkTokenStore>(passwords);

        await SweepAsync(services);

        await Assert.That(passwords.MagicLinkTokens.Select(token => token.TokenHash)).IsEquivalentTo(["live"]);
    }

    private static ToamaisutaaInvitationToken Invitation(string tokenHash, DateTimeOffset expiresAt) =>
        new()
        {
            Id = Guid.CreateVersion7(Now),
            UserId = Guid.CreateVersion7(Now),
            TokenHash = tokenHash,
            CreatedAt = Now,
            ExpiresAt = expiresAt,
        };

    private static ToamaisutaaMagicLinkToken MagicLink(string tokenHash, DateTimeOffset expiresAt) =>
        new()
        {
            Id = Guid.CreateVersion7(Now),
            UserId = Guid.CreateVersion7(Now),
            TokenHash = tokenHash,
            CreatedAt = Now,
            ExpiresAt = expiresAt,
        };

    private static async Task SweepAsync(FakeServiceProvider services, ILogger<TokenCleanupService>? logger = null)
    {
        using var service = new TokenCleanupService(
            new FakeServiceScopeFactory(services),
            Options.Create(new ToamaisutaaLocalLoginOptions()),
            new FixedTimeProvider(Now),
            logger ?? new CapturingLogger<TokenCleanupService>());

        await service.CleanupAsync(CancellationToken.None);
    }
}

/// <summary>The cleanup service takes a scope per sweep. This is the smallest thing that hands one
/// out without building a container.</summary>
internal sealed class FakeServiceScopeFactory(FakeServiceProvider services) : IServiceScopeFactory, IServiceScope
{
    public IServiceProvider ServiceProvider => services;

    public IServiceScope CreateScope() => this;

    public void Dispose()
    {
    }
}

/// <summary>Keeps every line and its structured values, so a test can assert on a count that is
/// only ever reported through the log.</summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    internal List<(LogLevel Level, IReadOnlyDictionary<string, object?> Values)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state as IReadOnlyList<KeyValuePair<string, object?>> ?? [];
        Entries.Add((logLevel, values.ToDictionary(pair => pair.Key, pair => pair.Value)));
    }
}
