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
