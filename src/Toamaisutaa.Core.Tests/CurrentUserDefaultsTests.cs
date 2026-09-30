using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// The <c>ICurrentUser</c> defaults are the contract for every non-HTTP implementation, so they are
/// asserted rather than assumed.
/// </summary>
public class CurrentUserDefaultsTests
{
    private sealed class SubjectOnlyCurrentUser : ICurrentUser
    {
        public bool IsAuthenticated => true;

        public string? Subject => "abc-123";

        public string? Name => "nightly-import";

        public Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class RoleCarryingCurrentUser : ICurrentUser
    {
        public bool IsAuthenticated => true;

        public string? Subject => "abc-123";

        public string? Name => "nightly-import";

        public IReadOnlyList<string> Roles => ["archivist"];

        public Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    [Test]
    public async Task AnImplementationWithNoClaimsAnswersEmpty()
    {
        ICurrentUser currentUser = new SubjectOnlyCurrentUser();

        await Assert.That(currentUser.Roles).IsEmpty();
        await Assert.That(currentUser.IsInRole("archivist")).IsFalse();
        await Assert.That(currentUser.FindClaim("sub")).IsNull();
    }

    [Test]
    public async Task IsInRoleAnswersFromRolesAlone()
    {
        ICurrentUser currentUser = new RoleCarryingCurrentUser();

        await Assert.That(currentUser.IsInRole("archivist")).IsTrue();
        await Assert.That(currentUser.IsInRole("gatekeeper")).IsFalse();

        // Ordinal, the same comparison RequireRole makes.
        await Assert.That(currentUser.IsInRole("Archivist")).IsFalse();
    }
}
