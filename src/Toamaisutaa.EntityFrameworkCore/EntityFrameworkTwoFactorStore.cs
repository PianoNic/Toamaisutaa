using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Enrolments, recovery codes and challenges. One class for the same reason the password stores
/// share one: a single <c>DbContext</c>, registered together, three separate interfaces.
/// </summary>
internal sealed class EntityFrameworkTwoFactorStore<TContext>(TContext context)
    : ITwoFactorStore, IRecoveryCodeStore, ITwoFactorChallengeStore
    where TContext : DbContext
{
    // ── Enrolments ──

    public async Task<ToamaisutaaUserTwoFactor?> FindAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUserTwoFactor>()
            .FirstOrDefaultAsync(enrolment => enrolment.UserId == userId, cancellationToken);

    public async Task UpsertAsync(ToamaisutaaUserTwoFactor enrolment, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrolment);

        var set = context.Set<ToamaisutaaUserTwoFactor>();

        // Add or Update rather than the provider's own upsert, because there is no portable one.
        // The tracked-instance check matters: BeginEnrolmentAsync reads the row first, so the
        // context may already be tracking the very entity being written back.
        var tracked = context.Entry(enrolment).State != EntityState.Detached
            || await set.AnyAsync(existing => existing.UserId == enrolment.UserId, cancellationToken);

        if (tracked)
            set.Update(enrolment);
        else
            set.Add(enrolment);

        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        // Detach first: ExecuteDelete goes straight to the database, and a tracked instance left
        // behind would be written back by the next SaveChanges on this request.
        var tracked = context.ChangeTracker.Entries<ToamaisutaaUserTwoFactor>()
            .FirstOrDefault(entry => entry.Entity.UserId == userId);

        if (tracked is not null)
            tracked.State = EntityState.Detached;

        await context.Set<ToamaisutaaUserTwoFactor>()
            .Where(enrolment => enrolment.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task RecordUsedStepAsync(Guid userId, long step, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUserTwoFactor>()
            .Where(enrolment => enrolment.UserId == userId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(enrolment => enrolment.LastUsedStep, step),
                cancellationToken);

    // ── Recovery codes ──

    public async Task ReplaceAllAsync(Guid userId, IReadOnlyList<ToamaisutaaRecoveryCode> codes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(codes);

        // Deleted outright rather than marked consumed. A spent code and a superseded one are both
        // dead, and keeping the old rows would only make CountUnusedAsync lie.
        await context.Set<ToamaisutaaRecoveryCode>()
            .Where(code => code.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        if (codes.Count == 0)
            return;

        context.Set<ToamaisutaaRecoveryCode>().AddRange(codes);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaRecoveryCode?> FindUnusedAsync(Guid userId, string codeHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .FirstOrDefaultAsync(
                code => code.UserId == userId && code.CodeHash == codeHash && code.ConsumedAt == null,
                cancellationToken);

    public async Task MarkConsumedAsync(Guid codeId, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .Where(code => code.Id == codeId && code.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(code => code.ConsumedAt, consumedAt), cancellationToken);

    public async Task<int> CountUnusedAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaRecoveryCode>()
            .CountAsync(code => code.UserId == userId && code.ConsumedAt == null, cancellationToken);

    // ── Challenges ──

    public async Task CreateAsync(ToamaisutaaTwoFactorChallenge challenge, CancellationToken cancellationToken = default)
    {
        context.Set<ToamaisutaaTwoFactorChallenge>().Add(challenge);
        await context.SaveChangesAsync(cancellationToken);
    }

    public async Task<ToamaisutaaTwoFactorChallenge?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .FirstOrDefaultAsync(challenge => challenge.TokenHash == tokenHash, cancellationToken);

    async Task ITwoFactorChallengeStore.MarkConsumedAsync(Guid challengeId, DateTimeOffset consumedAt, CancellationToken cancellationToken) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .Where(challenge => challenge.Id == challengeId && challenge.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(challenge => challenge.ConsumedAt, consumedAt), cancellationToken);

    public async Task<int> DeleteExpiredAsync(DateTimeOffset expiredBefore, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaTwoFactorChallenge>()
            .Where(challenge => challenge.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
}
