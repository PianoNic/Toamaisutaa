using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// A key entry the ring could not read has to refuse the host, in a process that only validates
/// tokens as much as in one that issues them.
/// </summary>
/// <remarks>
/// The ring never throws - it collects a bad entry into <c>Problems</c> - and the only reader of
/// that list was the password-login startup check. A resource server validating the tokens another
/// instance issued registers no password login, so a <c>Pem</c> that lost its line breaks in a
/// values file dropped the entry, the host started clean, and every token it was configured to
/// accept came back 401 with nothing anywhere naming the key. That is indistinguishable from an
/// expired token.
/// </remarks>
public class SigningKeyStartupCheckTests
{
    private const string Mangled = "-----BEGIN PRIVATE KEY----- not a key -----END PRIVATE KEY-----";

    /// <summary>
    /// Bearer only, and <c>LocalLogin</c> bound by the application rather than by the package -
    /// which is the only way a process that issues no token gets a key list at all.
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

        // The stores come with password login because the checks ahead of it in the queue insist on
        // them, and a host that fell over on those would never reach the one under test.
        await using var connection = new SqliteConnection("DataSource=:memory:");

        if (withPasswordLogin)
        {
            await connection.OpenAsync();
            builder.Services.AddToamaisutaaDbContext(db => db.UseSqlite(connection));

            // Which binds LocalLogin itself. Binding it here as well would append the key list to
            // itself and put every problem in the message twice for a reason that is not the one
            // under test.
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

    /// <summary>The other half of the assertion above: a check that fires on a good list would be a
    /// package that cannot be started at all.</summary>
    [Test]
    public async Task Starts_a_token_validating_process_on_a_key_that_parsed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var message = await StartAsync(key.ExportPkcs8PrivateKeyPem(), withPasswordLogin: false);

        await Assert.That(message).IsNull();
    }

    /// <summary>
    /// Two checks reading one list would otherwise print the same line twice, and a startup message
    /// that says everything twice is one nobody finishes reading. The password-login check keeps it,
    /// because it reports the whole misconfiguration in a single message.
    /// </summary>
    [Test]
    public async Task Reports_the_same_key_once_when_password_login_is_registered()
    {
        var message = await StartAsync(Mangled, withPasswordLogin: true);

        await Assert.That(message).IsNotNull();
        await Assert.That(message!).Contains("password login is registered but not usable");
        await Assert.That(message!.Split("LocalLogin:SigningKeys[0]:Pem").Length - 1).IsEqualTo(1);
    }
}
