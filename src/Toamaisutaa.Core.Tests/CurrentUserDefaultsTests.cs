using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// What <c>ICurrentUser</c> answers where there is no request to read claims off.
/// </summary>
/// <remarks>
/// The defaults are the contract for every implementation that is not the HTTP one - a worker, a
/// test double, an application that wrote its own - so they are asserted rather than assumed.
/// </remarks>
public class CurrentUserDefaultsTests
{
    /// <summary>Knows who it is and nothing else, which is the shape a non-HTTP implementation has.</summary>
    private sealed class SubjectOnlyCurrentUser : ICurrentUser
    {
        public bool IsAuthenticated => true;

        public string? Subject => "abc-123";

        public string? Name => "nightly-import";

        public Task<ToamaisutaaUser> GetOrProvisionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    /// <summary>Answers for roles and leaves the rest defaulted.</summary>
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

    // So supplying roles is the whole job: the role check follows from them rather than being a
    // second thing to get right.
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
