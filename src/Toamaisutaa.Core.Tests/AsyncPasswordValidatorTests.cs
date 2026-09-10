using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>
/// That every path which chooses a password consults <c>IPasswordValidator.ValidateAsync</c>.
/// </summary>
/// <remarks>
/// A validator that has to do I/O - a breach-list lookup is the case this exists for - can only
/// answer from the async method. A call site left on the synchronous one skips it silently: the
/// length rules still apply, every existing test still passes, and the breach check is simply never
/// asked. So this asserts one path per method rather than trusting six call sites were all changed
/// together.
/// </remarks>
public class AsyncPasswordValidatorTests
{
    private const string Refused = "This password is not allowed here.";

    /// <summary>
    /// Answers from the async method only, and only once armed - so the setup a test needs (a
    /// registration, a reset token, an invitation) goes through, and the call under test does not.
    /// A caller still on the synchronous method gets no errors at all.
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
