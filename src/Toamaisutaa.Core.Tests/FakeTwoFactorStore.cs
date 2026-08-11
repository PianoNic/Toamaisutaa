using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>Enrolments, recovery codes and challenges in memory, matching the shape of the Entity
/// Framework store closely enough that a flow exercised here is the flow that runs.</summary>
internal sealed class FakeTwoFactorStore : ITwoFactorStore, IRecoveryCodeStore, ITwoFactorChallengeStore
{
    internal List<ToamaisutaaUserTwoFactor> Enrolments { get; } = [];

    internal List<ToamaisutaaRecoveryCode> Codes { get; } = [];

    internal List<ToamaisutaaTwoFactorChallenge> Challenges { get; } = [];

    // ── Enrolments ──

    public Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Enrolments.FirstOrDefault(enrolment => enrolment.UserId == userId));

    public Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default)
    {
        Enrolments.RemoveAll(existing => existing.UserId == enrolment.UserId);
        Enrolments.Add(enrolment);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        Enrolments.RemoveAll(enrolment => enrolment.UserId == userId);
        return Task.CompletedTask;
    }

    public Task RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default)
    {
        var enrolment = Enrolments.FirstOrDefault(entry => entry.UserId == userId);

        if (enrolment is not null)
            enrolment.LastUsedStep = step;

        return Task.CompletedTask;
    }

    // ── Recovery codes ──

    public Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default)
    {
        Codes.RemoveAll(code => code.UserId == userId);
        Codes.AddRange(codes);
        return Task.CompletedTask;
    }

    public Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default) =>
        Task.FromResult(Codes.FirstOrDefault(code =>
            code.UserId == userId && code.CodeHash == codeHash && code.ConsumedAt is null));

    public Task MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var code = Codes.FirstOrDefault(entry => entry.Id == codeId);

        if (code is not null)
            code.ConsumedAt ??= consumedAt;

        return Task.CompletedTask;
    }

    public Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Codes.Count(code => code.UserId == userId && code.ConsumedAt is null));

    // ── Challenges ──

    public Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default)
    {
        Challenges.Add(challenge);
        return Task.CompletedTask;
    }

    public Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        Task.FromResult(Challenges.FirstOrDefault(challenge => challenge.TokenHash == tokenHash));

    Task ITwoFactorChallengeStore.MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken)
    {
        var challenge = Challenges.FirstOrDefault(entry => entry.Id == challengeId);

        if (challenge is not null)
            challenge.ConsumedAt ??= consumedAt;

        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        Task.FromResult(Challenges.RemoveAll(challenge => challenge.ExpiresAt <= expiredBefore));
}

/// <summary>
/// The two-factor services are resolved through a provider rather than a constructor, so that
/// password login works with none of them registered. This is the smallest thing that satisfies
/// that lookup without dragging a container into the tests.
/// </summary>
internal sealed class FakeServiceProvider : IServiceProvider
{
    private readonly Dictionary<Type, object> _services = [];

    internal FakeServiceProvider Add<T>(T instance) where T : notnull
    {
        _services[typeof(T)] = instance;
        return this;
    }

    public object? GetService(Type serviceType) =>
        _services.TryGetValue(serviceType, out var service) ? service : null;
}
