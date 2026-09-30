using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// A call site left on the synchronous <c>Validate</c> silently skips a validator that does I/O, so
/// every path that chooses a password is asserted to consult <c>ValidateAsync</c>.
/// </summary>
public class AsyncPasswordValidatorTests
{
    private const string Refused = "This password is not allowed here.";

    /// <summary>
    /// Answers from the async method only, and only once armed, so a test's setup goes through and
    /// the call under test does not.
    /// </summary>
    private sealed class AsyncOnlyValidator : IPasswordValidator
    {
        internal bool Armed { get; set; }

        public IReadOnlyList<string> Validate(string password) => [];

        public ValueTask<IReadOnlyList<string>> ValidateAsync(string password, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IReadOnlyList<string>>(Armed ? [Refused] : []);
    }

    private static (PasswordHarness Harness, AsyncOnlyValidator Validator) Armed()
    {
        var validator = new AsyncOnlyValidator();
        return (PasswordHarness.Create(validator: validator), validator);
    }

    [Test]
    public async Task RegisteringAsks()
    {
        var (harness, validator) = Armed();
        validator.Armed = true;

        var result = await harness.Accounts.RegisterAsync(new RegisterRequest("pianonic", "nic@example.com", "a long enough password"));

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }

    [Test]
    public async Task ChangingYourOwnPasswordAsks()
    {
        var (harness, validator) = Armed();
        var user = await harness.RegisterAsync();
        validator.Armed = true;

        var result = await harness.Accounts.SetPasswordAsync(user.Id, "correct horse battery", "another long enough password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }

    [Test]
    public async Task AnAdminCreatingAnAccountAsks()
    {
        var (harness, validator) = Armed();
        validator.Armed = true;

        var result = await harness.Accounts.AdminCreateAccountAsync("gatekeeper", "gate@example.com", "a long enough password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }

    [Test]
    public async Task AnAdminSettingAPasswordAsks()
    {
        var (harness, validator) = Armed();
        var user = await harness.RegisterAsync();
        validator.Armed = true;

        var result = await harness.Accounts.AdminSetPasswordAsync(user.Id, "another long enough password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }

    [Test]
    public async Task CompletingAnInvitationAsks()
    {
        var (harness, validator) = Armed();
        await harness.Accounts.CreateInvitationAsync("invited@example.com");
        var (_, token) = harness.InvitationNotifier.Sent.Single();
        validator.Armed = true;

        var result = await harness.Accounts.CompleteInvitationAsync(token, "invitee", "a long enough password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }

    [Test]
    public async Task ResettingAPasswordAsks()
    {
        var (harness, validator) = Armed();
        var user = await harness.RegisterAsync();
        await harness.Accounts.RequestPasswordResetAsync(user.Email!);
        var (_, token) = harness.Notifier.Sent.Single();
        validator.Armed = true;

        var result = await harness.Accounts.ResetPasswordAsync(token, "another long enough password");

        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Errors).IsEquivalentTo(new[] { Refused });
    }
}
