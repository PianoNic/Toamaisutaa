using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// Enough of the credential store for the one thing Core does with it: taking every passkey off an
/// account whose password has just been set.
/// </summary>
internal sealed class FakePasskeyStore : IPasskeyCredentialStore
{
    internal List<ToamaisutaaPasskeyCredential> Credentials { get; } = [];

    internal ToamaisutaaPasskeyCredential Add(Guid userId)
    {
        var credential = new ToamaisutaaPasskeyCredential
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            CredentialId = Guid.NewGuid().ToByteArray(),
            PublicKey = [1, 2, 3],
            CreatedAt = DateTimeOffset.UnixEpoch,
        };

        Credentials.Add(credential);
        return credential;
    }

    public Task<ToamaisutaaPasskeyCredential?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.FirstOrDefault(credential => credential.CredentialId.SequenceEqual(credentialId)));

    public Task<IReadOnlyList<ToamaisutaaPasskeyCredential>> ListAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ToamaisutaaPasskeyCredential>>([.. Credentials.Where(credential => credential.UserId == userId)]);

    public Task CreateAsync(ToamaisutaaPasskeyCredential credential, CancellationToken cancellationToken = default)
    {
        Credentials.Add(credential);
        return Task.CompletedTask;
    }

    public Task RecordUseAsync(
        Guid credentialId,
        long signCount,
        bool isBackedUp,
        DateTimeOffset usedAt,
        CancellationToken cancellationToken = default)
    {
        var credential = Credentials.FirstOrDefault(entry => entry.Id == credentialId);

        if (credential is not null)
        {
            credential.SignCount = signCount;
            credential.IsBackedUp = isBackedUp;
            credential.LastUsedAt = usedAt;
        }

        return Task.CompletedTask;
    }

    public Task<bool> DeleteAsync(Guid userId, Guid credentialId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.RemoveAll(credential => credential.Id == credentialId && credential.UserId == userId) > 0);

    public Task<int> DeleteAllAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.RemoveAll(credential => credential.UserId == userId));

    public Task<int> CountAsync(Guid userId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.Count(credential => credential.UserId == userId));
}
