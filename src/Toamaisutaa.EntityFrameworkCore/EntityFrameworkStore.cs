using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>Both stores in one per-request instance, so a lost first-sign-in race can tell whether
/// this request created the user and remove the orphan.</summary>
internal sealed class EntityFrameworkStore<TContext>(TContext context, TimeProvider timeProvider)
    : IUserStore, IExternalLoginStore
    where TContext : DbContext
{
    private readonly HashSet<Guid> _createdHere = [];

    public async Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUser>().FirstOrDefaultAsync(user => user.Id == id, cancellationToken);

    public async Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        // Upper-cased on both sides rather than trusting the collation; unindexed by design, since it
        // only decides what to write in a log line.
        var normalized = email.Trim().ToUpperInvariant();

        return await context.Set<ToamaisutaaUser>()
            .FirstOrDefaultAsync(user => user.Email != null && user.Email.ToUpper() == normalized, cancellationToken);
    }

    public async Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        var user = new ToamaisutaaUser
        {
            Id = Guid.CreateVersion7(now),
            UserName = profile.UserName,
            Email = profile.Email,
            DisplayName = profile.DisplayName,
            PictureUrl = profile.PictureUrl,
            SecurityStamp = NewSecurityStamp(),
            CreatedAt = now,
            UpdatedAt = now,
        };

        context.Set<ToamaisutaaUser>().Add(user);
        await context.SaveChangesAsync(cancellationToken);

        _createdHere.Add(user.Id);
        return user;
    }

    public async Task<ToamaisutaaUser> CreateAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        var now = timeProvider.GetUtcNow();

        user.Id = Guid.CreateVersion7(now);
        user.CreatedAt = now;
        user.UpdatedAt = now;

        if (string.IsNullOrEmpty(user.SecurityStamp))
            user.SecurityStamp = NewSecurityStamp();

        context.Set<ToamaisutaaUser>().Add(user);
        await context.SaveChangesAsync(cancellationToken);

        _createdHere.Add(user.Id);
        return user;
    }

    public async Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        _createdHere.Remove(userId);

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        var now = timeProvider.GetUtcNow();

        // Only the profile columns: writing the row back whole could restore a stale security stamp
        // and revive revoked tokens.
        await context.Set<ToamaisutaaUser>()
            .Where(stored => stored.Id == user.Id)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(stored => stored.UserName, profile.UserName)
                    .SetProperty(stored => stored.Email, profile.Email)
                    .SetProperty(stored => stored.DisplayName, profile.DisplayName)
                    .SetProperty(stored => stored.PictureUrl, profile.PictureUrl)
                    .SetProperty(stored => stored.UpdatedAt, now),
                cancellationToken);

        user.UserName = profile.UserName;
        user.Email = profile.Email;
        user.DisplayName = profile.DisplayName;
        user.PictureUrl = profile.PictureUrl;
        user.UpdatedAt = now;
    }

    public async Task UpdateSecurityStampAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(securityStamp);

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(user => user.SecurityStamp, securityStamp)
                    .SetProperty(user => user.UpdatedAt, timeProvider.GetUtcNow()),
                cancellationToken);
    }

    public async Task SetUserNameAsync(Guid userId, string userName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(user => user.UserName, userName)
                    .SetProperty(user => user.DisplayName, userName)
                    .SetProperty(user => user.UpdatedAt, timeProvider.GetUtcNow()),
                cancellationToken);
    }

    public async Task SetEmailAsync(Guid userId, string email, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(user => user.Email, email)
                    .SetProperty(user => user.UpdatedAt, timeProvider.GetUtcNow()),
                cancellationToken);
    }

    /// <summary>Every user gets one on creation, because a null stamp would make the refresh check
    /// always pass or always fail.</summary>
    private static string NewSecurityStamp() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public async Task<ToamaisutaaExternalLogin?> FindAsync(
        string providerKey,
        string subject,
        CancellationToken cancellationToken = default)
    {
        var candidates = await context.Set<ToamaisutaaExternalLogin>()
            .Where(login => login.ProviderKey == providerKey && login.Subject == subject)
            .ToListAsync(cancellationToken);

        // Re-compared ordinally: SQL Server's and MySQL's default collations ignore case (MySQL's also
        // accents), but an OpenID Connect subject is case-sensitive, so "Alice" would sign in as "alice".
        return candidates.FirstOrDefault(login =>
            string.Equals(login.ProviderKey, providerKey, StringComparison.Ordinal)
            && string.Equals(login.Subject, subject, StringComparison.Ordinal));
    }

    public async Task<ToamaisutaaExternalLogin> LinkAsync(
        Guid userId,
        string providerKey,
        ExternalUserProfile profile,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        var login = new ToamaisutaaExternalLogin
        {
            Id = Guid.CreateVersion7(now),
            UserId = userId,
            ProviderKey = providerKey,
            Subject = profile.Subject,
            Issuer = profile.Issuer,
            CreatedAt = now,
            LastSignInAt = now,
        };

        context.Set<ToamaisutaaExternalLogin>().Add(login);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
            return login;
        }
        catch (DbUpdateException exception)
        {
            context.Entry(login).State = EntityState.Detached;

            // Which constraint fired is provider-specific, so ask the database instead of parsing
            // an error code.
            var existing = await context.Set<ToamaisutaaExternalLogin>()
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    other => other.ProviderKey == providerKey && other.Subject == profile.Subject,
                    cancellationToken);

            if (existing is null)
                throw;

            await DiscardOrphanedUserAsync(userId, cancellationToken);
            throw new ExternalLoginConflictException(providerKey, profile.Subject, exception);
        }
    }

    public async Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default)
    {
        await context.Set<ToamaisutaaExternalLogin>()
            .Where(login => login.Id == externalLoginId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(login => login.LastSignInAt, timeProvider.GetUtcNow()),
                cancellationToken);
    }

    /// <summary>Only deletes a user this request created, so a pre-existing user is never touched.</summary>
    private async Task DiscardOrphanedUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (!_createdHere.Remove(userId))
            return;

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
