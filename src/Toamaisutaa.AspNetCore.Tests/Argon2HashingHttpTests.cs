using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Core;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Registered after <c>AddToamaisutaaPasswordLogin</c>, as a consumer does, which is the
/// order that would silently lose if the package used TryAdd.</summary>
public class Argon2HashingHttpTests
{
    private static Task<TestApp> StartAsync() =>
        TestApp.StartAsync(configureServices: services => services.AddToamaisutaaArgon2PasswordHashing());

    [Test]
    public async Task Registering_stores_an_argon2id_row()
    {
        await using var app = await StartAsync();
        await Account.RegisterAsync(app);

        await Assert.That(await StoredHashAsync(app)).StartsWith("$argon2id$v=19$");
    }

    [Test]
    public async Task Login_rewrites_a_pbkdf2_row_as_argon2id()
    {
        await using var app = await StartAsync();
        var account = await Account.RegisterAsync(app);

        await StoreAsync(app, app.Services.GetRequiredService<Pbkdf2PasswordHasher>().Hash(account.Password));

        var response = await account.LoginAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That((await response.Json()).String("access_token")).IsNotNull();
        await Assert.That(await StoredHashAsync(app)).StartsWith("$argon2id$v=19$");
    }

    [Test]
    public async Task A_wrong_password_against_a_pbkdf2_row_is_still_refused()
    {
        await using var app = await StartAsync();
        var account = await Account.RegisterAsync(app);

        await StoreAsync(app, app.Services.GetRequiredService<Pbkdf2PasswordHasher>().Hash("something else"));

        var response = await account.LoginAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await response.Json()).Has("access_token")).IsFalse();
        await Assert.That(await StoredHashAsync(app)).StartsWith("$pbkdf2-sha256$");
    }

    private static async Task<string> StoredHashAsync(TestApp app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();

        return await db.PasswordCredentials.AsNoTracking().Select(credential => credential.PasswordHash).SingleAsync();
    }

    private static async Task StoreAsync(TestApp app, string hash)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();

        var credential = await db.PasswordCredentials.SingleAsync();
        credential.PasswordHash = hash;

        await db.SaveChangesAsync();
    }
}
