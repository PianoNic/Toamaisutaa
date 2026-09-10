using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Core;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The Argon2 package behind the real pipeline. Everything it does is invisible from a response
/// body - the endpoints answer identically either way - so the only place the wiring can be
/// checked is the row the login left behind.
/// </summary>
/// <remarks>
/// Registered the way a consumer registers it, after <c>AddToamaisutaaPasswordLogin</c>, which is
/// the order that would silently lose if the package used TryAdd.
/// </remarks>
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

    /// <summary>
    /// The migration, end to end: a row from before the package was installed verifies through the
    /// PBKDF2 hasher, the sign-in succeeds, and the row is rewritten as Argon2id in the same
    /// transaction. No flag day, and nobody is locked out.
    /// </summary>
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

    /// <summary>The other half of the same claim: the PBKDF2 row is verified rather than waved
    /// through, so a wrong password against one is still a 401.</summary>
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

    /// <summary>Puts the account back the way it looked before this package was installed.</summary>
    private static async Task StoreAsync(TestApp app, string hash)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>();

        var credential = await db.PasswordCredentials.SingleAsync();
        credential.PasswordHash = hash;

        await db.SaveChangesAsync();
    }
}
