using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

public class PasswordSignInServiceTests
{
    private const string Password = "correct horse battery";

    [Test]
    public async Task SigningInWithTheRightPasswordReturnsAPair()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.SignIn.SignInAsync("pianonic", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(result.Tokens!.AccessToken).IsNotNull();
        await Assert.That(result.Tokens.RefreshToken).IsNotNull();
        await Assert.That(result.Tokens.TokenType).IsEqualTo("Bearer");
    }

    [Test]
    public async Task TheEmailWorksAsWellAsTheUserName()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.SignIn.SignInAsync("nic@example.com", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    [Arguments("PIANONIC")]
    [Arguments("Nic@Example.COM")]
    [Arguments("  pianonic  ")]
    public async Task IdentifiersAreCaseAndWhitespaceInsensitive(string identifier)
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.SignIn.SignInAsync(identifier, Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    // The two cases the caller must not be able to tell apart. They differ here, in the outcome the
    // log records; the endpoint collapses both into one response.
    [Test]
    public async Task UnknownUserAndWrongPasswordAreDistinctInternallyAndBothFail()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var unknown = await harness.SignIn.SignInAsync("nobody", Password);
        var wrong = await harness.SignIn.SignInAsync("pianonic", "not the password");

        await Assert.That(unknown.Outcome).IsEqualTo(SignInOutcome.UnknownUser);
        await Assert.That(wrong.Outcome).IsEqualTo(SignInOutcome.InvalidPassword);

        await Assert.That(unknown.Succeeded).IsFalse();
        await Assert.That(wrong.Succeeded).IsFalse();
        await Assert.That(unknown.Tokens).IsNull();
        await Assert.That(wrong.Tokens).IsNull();
    }

    [Test]
    public async Task LockoutFiresAtTheThreshold()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        for (var attempt = 0; attempt < 5; attempt++)
            await harness.SignIn.SignInAsync("pianonic", "wrong");

        // Even the right password is refused now, and refused the same way as everything else.
        var result = await harness.SignIn.SignInAsync("pianonic", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.LockedOut);
    }

    [Test]
    public async Task SigningInWorksAgainOnceTheLockExpires()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        for (var attempt = 0; attempt < 5; attempt++)
            await harness.SignIn.SignInAsync("pianonic", "wrong");

        harness.Clock.Now = harness.Clock.Now + harness.Options.LockoutDuration + TimeSpan.FromSeconds(1);

        var result = await harness.SignIn.SignInAsync("pianonic", Password);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task ASuccessfulSignInClearsTheFailureCount()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        for (var attempt = 0; attempt < 4; attempt++)
            await harness.SignIn.SignInAsync("pianonic", "wrong");

        await harness.SignIn.SignInAsync("pianonic", Password);

        await Assert.That(harness.Passwords.Credentials.Single().FailedAttemptCount).IsEqualTo(0);
    }

    [Test]
    public async Task AWeaklyHashedPasswordIsRewrittenOnSignIn()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var before = harness.Passwords.Credentials.Single().PasswordHash;

        // The deployment raises its iteration count.
        harness.Options.Pbkdf2Iterations *= 2;

        var result = await harness.SignIn.SignInAsync("pianonic", Password);
        var after = harness.Passwords.Credentials.Single().PasswordHash;

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(after).IsNotEqualTo(before);
        await Assert.That(after).Contains($"i={harness.Options.Pbkdf2Iterations}");
    }

    // ── Refresh ──

    [Test]
    public async Task RefreshingReturnsANewPairAndRetiresTheOldToken()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var first = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;
        var second = await harness.SignIn.RefreshAsync(first.RefreshToken);

        await Assert.That(second.Outcome).IsEqualTo(SignInOutcome.Succeeded);
        await Assert.That(second.Tokens!.RefreshToken).IsNotEqualTo(first.RefreshToken);

        var third = await harness.SignIn.RefreshAsync(second.Tokens.RefreshToken);
        await Assert.That(third.Outcome).IsEqualTo(SignInOutcome.Succeeded);
    }

    [Test]
    public async Task RotationKeepsTheFamilyAndItsStartTime()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var first = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;
        var issued = harness.Passwords.RefreshTokens[^1];

        harness.Clock.Now = harness.Clock.Now.AddDays(1);
        await harness.SignIn.RefreshAsync(first.RefreshToken);

        var rotated = harness.Passwords.RefreshTokens[^1];

        await Assert.That(rotated.FamilyId).IsEqualTo(issued.FamilyId);

        // A day later, and the family is still dated from the sign-in that started it - which is
        // what stops rotation from extending a session for ever.
        await Assert.That(rotated.FamilyStartedAt).IsEqualTo(issued.FamilyStartedAt);
        await Assert.That(rotated.CreatedAt).IsNotEqualTo(issued.CreatedAt);
    }

    // The stolen-token case. Both holders lose the chain, because there is no way to tell which one
    // is the owner.
    [Test]
    public async Task PresentingARotatedTokenAgainRevokesTheWholeFamily()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var first = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;
        var family = harness.Passwords.RefreshTokens[^1].FamilyId;
        var second = (await harness.SignIn.RefreshAsync(first.RefreshToken)).Tokens!;

        var reuse = await harness.SignIn.RefreshAsync(first.RefreshToken);

        await Assert.That(reuse.Outcome).IsEqualTo(SignInOutcome.RefreshTokenReused);

        // The token the thief's victim was still holding is dead too.
        var afterwards = await harness.SignIn.RefreshAsync(second.RefreshToken);
        await Assert.That(afterwards.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);

        var chain = harness.Passwords.RefreshTokens.Where(token => token.FamilyId == family).ToList();

        await Assert.That(chain.Count).IsEqualTo(2);
        await Assert.That(chain.All(token => token.RevokedAt is not null)).IsTrue();
        await Assert.That(chain.All(token => token.RevokedReason == "refresh-token-reuse")).IsTrue();

        // Only that chain. A session started from a different sign-in is somebody else's problem.
        await Assert.That(harness.Passwords.RefreshTokens.Any(token => token.FamilyId != family && token.RevokedAt is null)).IsTrue();
    }

    [Test]
    public async Task AnUnknownRefreshTokenIsRefused()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var result = await harness.SignIn.RefreshAsync("not-a-real-token");

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.InvalidRefreshToken);
    }

    [Test]
    public async Task AnExpiredRefreshTokenIsRefused()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var tokens = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;
        harness.Clock.Now = harness.Clock.Now + harness.Options.RefreshTokenLifetime + TimeSpan.FromSeconds(1);

        var result = await harness.SignIn.RefreshAsync(tokens.RefreshToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.RefreshTokenExpired);
    }

    // Rotation alone would keep a session alive for ever. The family's own age ends it.
    [Test]
    public async Task AFamilyPastItsAbsoluteLifetimeIsRefusedEvenWhileRotating()
    {
        var harness = PasswordHarness.Create(options =>
        {
            options.RefreshTokenLifetime = TimeSpan.FromDays(14);
            options.RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(30);
        });

        await harness.RegisterAsync();
        var tokens = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;

        // Refresh every ten days, so no single token ever expires.
        for (var day = 0; day < 3; day++)
        {
            harness.Clock.Now = harness.Clock.Now.AddDays(10);
            var refreshed = await harness.SignIn.RefreshAsync(tokens.RefreshToken);

            if (refreshed.Outcome != SignInOutcome.Succeeded)
            {
                await Assert.That(refreshed.Outcome).IsEqualTo(SignInOutcome.RefreshTokenExpired);
                await Assert.That(day).IsEqualTo(2);
                return;
            }

            tokens = refreshed.Tokens!;
        }

        Assert.Fail("The family outlived its absolute lifetime.");
    }

    [Test]
    public async Task SigningOutRevokesTheFamily()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        var tokens = (await harness.SignIn.SignInAsync("pianonic", Password)).Tokens!;
        await harness.SignIn.SignOutAsync(tokens.RefreshToken);

        var result = await harness.SignIn.RefreshAsync(tokens.RefreshToken);

        await Assert.That(result.Outcome).IsEqualTo(SignInOutcome.RefreshTokenRevoked);
    }

    [Test]
    public async Task SigningOutWithAnUnknownTokenDoesNothingAndSaysNothing()
    {
        var harness = PasswordHarness.Create();
        await harness.RegisterAsync();

        await harness.SignIn.SignOutAsync("not-a-real-token");

        await Assert.That(harness.Passwords.RefreshTokens.Any(token => token.RevokedAt is not null)).IsFalse();
    }
}
