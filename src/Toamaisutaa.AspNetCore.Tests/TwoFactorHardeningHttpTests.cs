using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>The smaller two-factor and passkey edges, one test each.</summary>
public class TwoFactorHardeningHttpTests
{
    [Test]
    public async Task Under_RequiredForAll_a_user_who_has_not_enrolled_reaches_only_the_enrolment_endpoints()
    {
        await using var app = await TestApp.StartAsync(configure: settings => settings["TwoFactor:Enforcement"] = "RequiredForAll");
        var account = await Account.RegisterAsync(app);

        var elsewhere = await app.Client.Get("/auth/sessions", account.AccessToken);
        var status = await app.Client.Get("/auth/2fa", account.AccessToken);

        await Assert.That(elsewhere.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That((await elsewhere.Json()).String("error")).IsEqualTo("two_factor_enrolment_required");
        await Assert.That(status.StatusCode).IsEqualTo(HttpStatusCode.OK);

        await account.EnrolAsync();

        await Assert.That((await app.Client.Get("/auth/sessions", account.AccessToken)).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Startup_refuses_two_factor_with_lockout_off()
    {
        var started = async () =>
        {
            await using var app = await TestApp.StartAsync(configure: settings => settings["LocalLogin:LockoutEnabled"] = "false");
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("LockoutEnabled");
    }

    /// <summary>Two assertions verified at once against the same stored counter land in either order.</summary>
    [Test]
    public async Task A_passkey_counter_never_moves_backwards()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        using var authenticator = new SoftwareAuthenticator();
        await Passkeys.RegisterAsync(app, account.AccessToken, authenticator);

        await using var scope = app.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<IPasskeyCredentialStore>();
        var passkey = (await store.ListAsync(Guid.Parse(account.Claims().String("sub")!))).Single();

        await store.RecordUseAsync(passkey.Id, 10, isBackedUp: false, app.Time.Now);
        await store.RecordUseAsync(passkey.Id, 5, isBackedUp: false, app.Time.Now);

        // A fresh scope: this one's change tracker still holds the row as listed above.
        await using var reading = app.Services.CreateAsyncScope();
        var stored = await reading.ServiceProvider.GetRequiredService<IPasskeyCredentialStore>().FindByCredentialIdAsync(passkey.CredentialId);

        await Assert.That(stored!.SignCount).IsEqualTo(10);
    }

    /// <summary>Somebody with write access to the table copies their own enrolment into another
    /// account's row, and signs in there with codes from their own authenticator.</summary>
    [Test]
    public async Task A_totp_secret_copied_into_another_account_s_row_does_not_work_there()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await Account.RegisterAsync(app, "victim");
        var intruder = await Account.RegisterAsync(app, "intruder");
        await victim.EnrolAsync();
        await intruder.EnrolAsync();

        var victimId = Guid.Parse(victim.Claims().String("sub")!);
        var intruderId = Guid.Parse(intruder.Claims().String("sub")!);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();
            var source = await db.UserTwoFactors.SingleAsync(row => row.UserId == intruderId);
            var target = await db.UserTwoFactors.SingleAsync(row => row.UserId == victimId);

            target.SecretCiphertext = source.SecretCiphertext;
            target.SecretNonce = source.SecretNonce;
            target.SecretTag = source.SecretTag;
            target.EncryptionKeyVersion = source.EncryptionKeyVersion;
            await db.SaveChangesAsync();
        }

        var challenge = (await (await victim.LoginAsync()).Json()).String("challenge")!;
        app.Time.AdvanceToNextTotpStep();

        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = Totp.Code(intruder.Secret!, app.Time.Now) });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>Bound from the moment it is stored, not only from its first use, which rewraps an
    /// unbound row and would otherwise hide that the enrolment wrote one.</summary>
    [Test]
    public async Task A_totp_secret_is_stored_bound_to_its_user_as_soon_as_enrolment_begins()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);

        await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);

        await using var scope = app.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>().UserTwoFactors.SingleAsync();

        await Assert.That(stored.EncryptionKeyVersion).EndsWith(":u");
    }

    [Test]
    public async Task Disabling_two_factor_takes_the_password_as_well_as_a_code()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        app.Time.AdvanceToNextTotpStep();
        var codeOnly = await app.Client.PostJson("/auth/2fa/disable", new { proof = Totp.Code(account.Secret!, app.Time.Now) }, account.AccessToken);

        app.Time.AdvanceToNextTotpStep();
        var both = await app.Client.PostJson(
            "/auth/2fa/disable",
            new { proof = Totp.Code(account.Secret!, app.Time.Now), currentPassword = account.Password },
            account.AccessToken);

        await Assert.That(codeOnly.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(both.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    [Test]
    public async Task Regenerating_recovery_codes_takes_the_password_as_well_as_a_code()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        app.Time.AdvanceToNextTotpStep();
        var codeOnly = await app.Client.PostJson("/auth/2fa/recovery-codes", new { proof = Totp.Code(account.Secret!, app.Time.Now) }, account.AccessToken);

        await Assert.That(codeOnly.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
    }

    [Test]
    public async Task Removing_a_passkey_from_an_account_with_totp_takes_a_code()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();
        using var authenticator = new SoftwareAuthenticator();
        app.Time.AdvanceToNextTotpStep();
        var registered = await Passkeys.RegisterAsync(app, account.AccessToken, authenticator, code: Totp.Code(account.Secret!, app.Time.Now));
        var id = (await registered.Json()).String("id")!;

        var passwordOnly = await app.Client.Delete($"/auth/passkeys/{id}", new { currentPassword = account.Password }, account.AccessToken);

        app.Time.AdvanceToNextTotpStep();
        var withCode = await app.Client.Delete($"/auth/passkeys/{id}", new { code = Totp.Code(account.Secret!, app.Time.Now) }, account.AccessToken);

        await Assert.That(passwordOnly.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(withCode.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }

    [Test]
    public async Task Startup_refuses_passkeys_without_the_cleanup_sweep()
    {
        var started = async () =>
        {
            await using var app = await TestApp.StartAsync(configureServices: services =>
            {
                foreach (var sweep in services.Where(descriptor => descriptor.ImplementationType == typeof(TokenCleanupService)).ToList())
                    services.Remove(sweep);
            });
        };

        var thrown = await Assert.That(started).Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).Contains("AddToamaisutaaTokenCleanup");
    }
}
