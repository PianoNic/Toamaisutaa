using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// How recovery codes sit in the table. About fifty bits each, so what matters is whether a copy of
/// the table is enough to recover them.
/// </summary>
public class RecoveryCodeStorageHttpTests
{
    /// <summary>
    /// Stored as plain SHA-256, every user's codes fell to one offline sweep of the whole code space.
    /// Keyed, the table alone does not have what it takes to check a guess.
    /// </summary>
    [Test]
    public async Task A_recovery_code_is_not_stored_as_its_plain_hash()
    {
        await using var app = await TestApp.StartAsync();
        var (account, codes) = await EnrolAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await using var scope = app.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<IRecoveryCodeStore>();

        var plain = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(codes[0]));

        await Assert.That(await store.FindUnusedAsync(userId, plain)).IsNull();
        await Assert.That(await store.CountUnusedAsync(userId)).IsEqualTo(codes.Count);
    }

    [Test]
    public async Task A_keyed_recovery_code_still_signs_in()
    {
        await using var app = await TestApp.StartAsync();
        var (account, codes) = await EnrolAsync(app);

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");
        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = codes[0] });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// Codes printed before codes were keyed are still somebody's only way back in, so the old form
    /// is still accepted until the set is regenerated.
    /// </summary>
    [Test]
    public async Task A_code_stored_the_old_way_still_signs_in()
    {
        await using var app = await TestApp.StartAsync();
        var (account, _) = await EnrolAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        const string legacy = "ABCDE-FGHJK";

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IRecoveryCodeStore>().ReplaceAllAsync(
                userId,
                [new ToamaisutaaRecoveryCode
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    CodeHash = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(legacy)),
                    CreatedAt = app.Time.Now,
                }]);
        }

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");
        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = legacy });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    /// <summary>
    /// The unkeyed hash is what a copy of the table gives up to a sweep, so an operator has to be
    /// able to stop accepting it once the stragglers have regenerated.
    /// </summary>
    [Test]
    public async Task A_code_stored_the_old_way_is_refused_once_unkeyed_codes_are_turned_off()
    {
        await using var app = await TestApp.StartAsync(configure: settings => settings["TwoFactor:AcceptUnkeyedRecoveryCodes"] = "false");
        var (account, _) = await EnrolAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        const string legacy = "ABCDE-FGHJK";

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IRecoveryCodeStore>().ReplaceAllAsync(
                userId,
                [new ToamaisutaaRecoveryCode
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    CodeHash = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(legacy)),
                    CreatedAt = app.Time.Now,
                }]);
        }

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");
        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code = legacy });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>The unkeyed hash is tried only against rows stored that way, so a code is never
    /// accepted as something its row never was.</summary>
    [Test]
    public async Task The_unkeyed_hash_is_not_tried_against_a_keyed_row()
    {
        await using var app = await TestApp.StartAsync();
        var (account, _) = await EnrolAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        const string code = "ABCDE-FGHJK";

        await using (var scope = app.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IRecoveryCodeStore>().ReplaceAllAsync(
                userId,
                [new ToamaisutaaRecoveryCode
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    CodeHash = SecureTokens.HashToken(RecoveryCodeProvider.Normalize(code)),
                    HashVersion = 1,
                    CreatedAt = app.Time.Now,
                }]);
        }

        var challenge = (await (await account.LoginAsync()).Json()).String("challenge");
        var verify = await app.Client.PostJson("/auth/2fa/verify", new { challenge, code });

        await Assert.That(verify.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// New codes are marked keyed, which is what lets the old ones be counted - both forms are the
    /// same length, and nothing else in the row tells them apart.
    /// </summary>
    [Test]
    public async Task A_new_code_is_marked_as_keyed()
    {
        await using var app = await TestApp.StartAsync();
        var (account, _) = await EnrolAsync(app);
        var userId = Guid.Parse(account.Claims().String("sub")!);

        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<Toamaisutaa.EntityFrameworkCore.ToamaisutaaDbContext>();

        var versions = db.RecoveryCodes.Where(code => code.UserId == userId).Select(code => code.HashVersion).Distinct().ToList();

        await Assert.That(versions).IsEquivalentTo(new[] { 1 });
    }

    private static async Task<(Account Account, IReadOnlyList<string> Codes)> EnrolAsync(TestApp app)
    {
        var account = await Account.RegisterAsync(app);

        var begin = await app.Client.PostJson("/auth/2fa/begin", new { currentPassword = account.Password }, account.AccessToken);
        var secret = (await begin.Json()).String("secret")!;

        app.Time.AdvanceToNextTotpStep();
        var confirm = await (await app.Client.PostJson(
            "/auth/2fa/confirm",
            new { code = Totp.Code(secret, app.Time.Now) },
            account.AccessToken)).Json();

        return (account, confirm.Strings("recoveryCodes"));
    }
}
