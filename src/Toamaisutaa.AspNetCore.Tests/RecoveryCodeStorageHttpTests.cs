using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

public class RecoveryCodeStorageHttpTests
{
    /// <summary>
    /// Codes carry about fifty bits, so a plain SHA-256 table falls to one offline sweep of the code space.
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
    /// Keyed and unkeyed hashes are the same length, so the version marker is the only way to tell old rows apart.
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
        return (account, await account.EnrolForRecoveryCodesAsync());
    }
}
