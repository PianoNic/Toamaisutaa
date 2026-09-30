using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class CredentialWritesTests
{
    /// <summary>
    /// Every attempt costs about two writes to one row, so twenty parallel second factors make a
    /// request lose more than ten writes in a row; against the real store a limit of ten failed.
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
