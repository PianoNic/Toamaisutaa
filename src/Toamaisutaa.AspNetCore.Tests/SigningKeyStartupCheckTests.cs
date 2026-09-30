using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The ring collects a bad entry into <c>Problems</c> rather than throwing, so a bearer-only host
/// without its own check starts clean and answers 401 to every token with nothing naming the key.
/// </summary>
public class SigningKeyStartupCheckTests
{
    private const string Mangled = "-----BEGIN PRIVATE KEY----- not a key -----END PRIVATE KEY-----";

    /// <summary>
    /// Without password login, <c>LocalLogin</c> is bound by the application, which is the only way a
    /// process that issues no token gets a key list at all.
    /// </summary>
    private static async Task<string?> StartAsync(string pem, bool withPasswordLogin)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.None);

        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:ClientId"] = "toamaisutaa-tests",
            ["LocalLogin:Issuer"] = "toamaisutaa-tests",
            ["LocalLogin:SigningKeys:0:Kid"] = "2026-09",
            ["LocalLogin:SigningKeys:0:Pem"] = pem,
        });

        builder.Services.AddToamaisutaaBearer(builder.Configuration);

        // The stores come with password login because earlier startup checks insist on them and would
        // otherwise fail before the one under test.
        await using var connection = new SqliteConnection("DataSource=:memory:");

        if (withPasswordLogin)
        {
            await connection.OpenAsync();
            builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(connection));

            // This binds LocalLogin itself; binding it here too would duplicate the key list and every problem.
            builder.Services.AddToamaisutaaPasswordLogin(builder.Configuration);
        }
        else
        {
            builder.Services.Configure<ToamaisutaaLocalLoginOptions>(builder.Configuration.GetSection("LocalLogin"));
        }

        var app = builder.Build();

        try
        {
            await app.StartAsync();
            return null;
        }
        catch (InvalidOperationException exception)
        {
            return exception.Message;
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Test]
    public async Task Refuses_to_start_a_token_validating_process_on_a_key_that_did_not_parse()
    {
        var message = await StartAsync(Mangled, withPasswordLogin: false);

        await Assert.That(message).IsNotNull();
        await Assert.That(message!).Contains("LocalLogin:SigningKeys[0]:Pem is not a PEM-encoded RSA or EC key.");
    }

    [Test]
    public async Task Starts_a_token_validating_process_on_a_key_that_parsed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var message = await StartAsync(key.ExportPkcs8PrivateKeyPem(), withPasswordLogin: false);

        await Assert.That(message).IsNull();
    }

    [Test]
    public async Task Reports_the_same_key_once_when_password_login_is_registered()
    {
        var message = await StartAsync(Mangled, withPasswordLogin: true);

        await Assert.That(message).IsNotNull();
        await Assert.That(message!).Contains("password login is registered but not usable");
        await Assert.That(message!.Split("LocalLogin:SigningKeys[0]:Pem").Length - 1).IsEqualTo(1);
    }
}
