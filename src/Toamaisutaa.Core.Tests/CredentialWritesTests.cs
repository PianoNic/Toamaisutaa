using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// How many times a credential write is retried before the request gives up.
/// </summary>
public class CredentialWritesTests
{
    /// <summary>
    /// Every attempt is now counted before it is checked and given back or cleared after, so a burst
    /// of parallel requests on one account is about two writes each to one row. Twenty second
    /// factors at once made a request lose more than ten writes in a row and answer 500 - reproduced
    /// against the real store, where the limit of ten failed and fifty did not.
    /// </summary>
    [Test]
    public async Task A_write_that_loses_to_a_burst_of_parallel_attempts_still_lands()
    {
        var inner = new FakePasswordStore();
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await inner.CreateAsync(credential);

        // Twenty requests, two writes each, and this one losing to every other.
        var store = new LosesFirst(inner, times: 39);

        var written = await store.UpdateAsync(credential, current => current.FailedAttemptCount++, CancellationToken.None);

        await Assert.That(written.FailedAttemptCount).IsGreaterThan(0);
    }

    /// <summary>The other side of the limit: a write that never lands still stops, rather than
    /// looping for as long as something keeps winning.</summary>
    [Test]
    public async Task A_write_that_never_lands_gives_up()
    {
        var inner = new FakePasswordStore();
        var credential = new ToamaisutaaPasswordCredential { UserId = Guid.NewGuid(), UserName = "ada", NormalizedUserName = "ADA", PasswordHash = "h" };
        await inner.CreateAsync(credential);

        var store = new LosesFirst(inner, times: int.MaxValue);

        await Assert.That(async () => await store.UpdateAsync(credential, current => current.FailedAttemptCount++, CancellationToken.None))
            .Throws<CredentialConcurrencyException>();
    }

    /// <summary>A store whose first writes all find the row already changed.</summary>
    private sealed class LosesFirst(FakePasswordStore inner, int times) : IPasswordCredentialStore
    {
        private int _lost;

        public Task<ToamaisutaaPasswordCredential?> FindByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.FindByUserIdAsync(userId, cancellationToken);

        public Task<ToamaisutaaPasswordCredential?> FindByIdentifierAsync(string normalizedIdentifier, CancellationToken cancellationToken = default) =>
            inner.FindByIdentifierAsync(normalizedIdentifier, cancellationToken);

        public Task<ToamaisutaaPasswordCredential?> FindByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
            inner.FindByNormalizedEmailAsync(normalizedEmail, cancellationToken);

        public Task CreateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
            inner.CreateAsync(credential, cancellationToken);

        public Task UpdateAsync(ToamaisutaaPasswordCredential credential, CancellationToken cancellationToken = default) =>
            _lost++ < times ? throw new CredentialConcurrencyException() : inner.UpdateAsync(credential, cancellationToken);
    }
}
