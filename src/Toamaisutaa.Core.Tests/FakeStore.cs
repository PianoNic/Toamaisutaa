using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>Both stores in memory, with a switch for simulating a lost race on the unique index.</summary>
internal sealed class FakeStore(TimeProvider timeProvider) : IUserStore, IExternalLoginStore
{
    internal List<ToamaisutaaUser> Users { get; } = [];

    internal List<ToamaisutaaExternalLogin> Logins { get; } = [];

    internal int ProfileUpdates { get; private set; }

    internal int SignInStamps { get; private set; }

    internal int LinkAttempts { get; private set; }

    /// <summary>When set, the next link attempt loses: another request's row appears and the unique
    /// index rejects ours.</summary>
    internal ToamaisutaaUser? WinnerOfTheNextRace { get; set; }

    public Task<ToamaisutaaUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        Task.FromResult(Users.FirstOrDefault(user => user.Id == id));

    public Task<ToamaisutaaUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var normalized = email.Trim().ToUpperInvariant();

        return Task.FromResult(Users.FirstOrDefault(
            user => user.Email is not null && string.Equals(user.Email.ToUpperInvariant(), normalized, StringComparison.Ordinal)));
    }

    public Task<ToamaisutaaUser> CreateAsync(ToamaisutaaUser user, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        user.Id = Guid.CreateVersion7(now);
        user.CreatedAt = now;
        user.UpdatedAt = now;

        Users.Add(user);
        return Task.FromResult(user);
    }

    public Task DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        Users.RemoveAll(user => user.Id == userId);
        return Task.CompletedTask;
    }

    public Task<ToamaisutaaUser> CreateAsync(ExternalUserProfile profile, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        var user = new ToamaisutaaUser
        {
            Id = Guid.CreateVersion7(now),
            UserName = profile.UserName,
            Email = profile.Email,
            DisplayName = profile.DisplayName,
            PictureUrl = profile.PictureUrl,
            CreatedAt = now,
            UpdatedAt = now,
        };

        Users.Add(user);
        return Task.FromResult(user);
    }

    public Task UpdateProfileAsync(ToamaisutaaUser user, ExternalUserProfile profile, CancellationToken cancellationToken = default)
    {
        user.UserName = profile.UserName;
        user.Email = profile.Email;
        user.DisplayName = profile.DisplayName;
        user.PictureUrl = profile.PictureUrl;
        user.UpdatedAt = timeProvider.GetUtcNow();

        ProfileUpdates++;
        return Task.CompletedTask;
    }

    public Task<ToamaisutaaExternalLogin?> FindAsync(string providerKey, string subject, CancellationToken cancellationToken = default) =>
        Task.FromResult(Logins.FirstOrDefault(login => login.ProviderKey == providerKey && login.Subject == subject));

    public Task<ToamaisutaaExternalLogin> LinkAsync(
        Guid userId,
        string providerKey,
        ExternalUserProfile profile,
        CancellationToken cancellationToken = default)
    {
        LinkAttempts++;

        if (WinnerOfTheNextRace is { } winner)
        {
            WinnerOfTheNextRace = null;

            Users.Add(winner);
            Logins.Add(new ToamaisutaaExternalLogin
            {
                Id = Guid.CreateVersion7(timeProvider.GetUtcNow()),
                UserId = winner.Id,
                ProviderKey = providerKey,
                Subject = profile.Subject,
                CreatedAt = timeProvider.GetUtcNow(),
                LastSignInAt = timeProvider.GetUtcNow(),
            });

            throw new ExternalLoginConflictException(providerKey, profile.Subject);
        }

        if (Logins.Any(login => login.ProviderKey == providerKey && login.Subject == profile.Subject))
            throw new ExternalLoginConflictException(providerKey, profile.Subject);

        var created = new ToamaisutaaExternalLogin
        {
            Id = Guid.CreateVersion7(timeProvider.GetUtcNow()),
            UserId = userId,
            ProviderKey = providerKey,
            Subject = profile.Subject,
            Issuer = profile.Issuer,
            CreatedAt = timeProvider.GetUtcNow(),
            LastSignInAt = timeProvider.GetUtcNow(),
        };

        Logins.Add(created);
        return Task.FromResult(created);
    }

    public Task RecordSignInAsync(Guid externalLoginId, CancellationToken cancellationToken = default)
    {
        var login = Logins.First(entry => entry.Id == externalLoginId);
        login.LastSignInAt = timeProvider.GetUtcNow();

        SignInStamps++;
        return Task.CompletedTask;
    }
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    internal DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}
