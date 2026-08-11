using Microsoft.EntityFrameworkCore;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.EntityFrameworkCore;

/// <summary>
/// Both stores in one class, registered once per request and exposed under both interfaces. They
/// share a <c>DbContext</c> anyway, and one object can tell whether the user it is linking was
/// created moments ago by this same request - which is what makes the concurrent first sign-in
/// clean up after itself instead of leaving a user row with no login attached.
/// </summary>
internal sealed class EntityFrameworkStore<TContext>(TContext context, TimeProvider timeProvider)
    : IUserStore, IExternalLoginStore
    where TContext : DbContext
{
    private readonly HashSet<Guid> _createdHere = [];

    public async Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaUser>().FirstOrDefaultAsync(user => user.Id == id, cancellationToken);

    public async Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        // Upper-cased on both sides rather than trusting the database's collation, and unindexed by
        // design: the column is not unique, so this can match several rows and is only ever used to
        // decide what to write in a log line.
        var normalized = email.Trim().ToUpperInvariant();

        return await context.Set<ToamaisutaaUser>()
            .FirstOrDefaultAsync(user => user.Email != null && user.Email.ToUpper() == normalized, cancellationToken);
    }

    public async Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        var user = new ToamaisutaaUser
        {
            // Sequential, so the primary-key index does not fragment the way random Guids do.
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

        user.UserName = profile.UserName;
        user.Email = profile.Email;
        user.DisplayName = profile.DisplayName;
        user.PictureUrl = profile.PictureUrl;
        user.UpdatedAt = timeProvider.GetUtcNow();

        // Covers the case where the caller handed back a detached instance.
        context.Set<ToamaisutaaUser>().Update(user);
        await context.SaveChangesAsync(cancellationToken);
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

    /// <summary>
    /// Every user gets one from the moment the row exists, including one provisioned from an
    /// identity provider that will never have a password. A null stamp compares equal to nothing
    /// and would make the refresh check either always pass or always fail, depending on which side
    /// was missing.
    /// </summary>
    private static string NewSecurityStamp() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public async Task<ToamaisutaaExternalLogin?> FindAsync(
        string providerKey,
        string subject,
        CancellationToken cancellationToken = default) =>
        await context.Set<ToamaisutaaExternalLogin>()
            .FirstOrDefaultAsync(
                login => login.ProviderKey == providerKey && login.Subject == subject,
                cancellationToken);

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
            // an error code: if the pair is there now and we did not put it there, we lost a race.
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

    /// <summary>
    /// The losing side of a concurrent first sign-in has just created a user that will never get a
    /// login, because the winner's row owns the subject now. Remove it - but only when this request
    /// is the one that created it, so a pre-existing user someone else owns is never touched.
    /// </summary>
    private async Task DiscardOrphanedUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (!_createdHere.Remove(userId))
            return;

        await context.Set<ToamaisutaaUser>()
            .Where(user => user.Id == userId)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
