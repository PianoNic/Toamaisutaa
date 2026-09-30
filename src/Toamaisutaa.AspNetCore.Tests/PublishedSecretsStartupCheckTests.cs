using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// Reads the sample's own settings file, so the test follows its keys and does not publish them a second time.
/// </summary>
public class PublishedSecretsStartupCheckTests
{
    [Test]
    [Arguments("signing")]
    [Arguments("pepper")]
    [Arguments("two-factor")]
    public async Task Refuses_to_start_outside_development_on_a_value_the_sample_publishes(string which)
    {
        var message = await StartAsync(which, Environments.Production);

        await Assert.That(message).IsNotNull();
        await Assert.That(message!).Contains("values from the public sample");
    }

    [Test]
    public async Task Starts_in_development_on_the_samples_values()
    {
        await Assert.That(await StartAsync("signing", Environments.Development)).IsNull();
    }

    /// <summary>Runs on a real server, because the test server has no bound addresses to judge.</summary>
    [Test]
    [Arguments("http://0.0.0.0:0", false)]
    [Arguments("http://127.0.0.1:0", true)]
    [Arguments("http://[::1]:0", true)]
    public async Task In_development_the_samples_values_are_served_on_loopback_only(string url, bool starts)
    {
        var message = await StartAsync("signing", Environments.Development, url);

        if (starts)
        {
            await Assert.That(message).IsNull();
        }
        else
        {
            await Assert.That(message).IsNotNull();
            await Assert.That(message!).Contains("not loopback");
        }
    }

    /// <summary>A same-host reverse proxy leaves the server bound to loopback, so only the request
    /// shows it came from elsewhere.</summary>
    [Test]
    public async Task In_development_the_samples_values_are_not_served_through_a_proxy()
    {
        HttpStatusCode? direct = null, proxied = null;

        var message = await StartAsync("signing", Environments.Development, whileRunning: async app =>
        {
            var client = app.GetTestClient();
            direct = (await client.GetAsync("/ping")).StatusCode;

            using var request = new HttpRequestMessage(HttpMethod.Get, "/ping");
            request.Headers.Add("X-Forwarded-For", "203.0.113.7");
            proxied = (await client.SendAsync(request)).StatusCode;
        });

        await Assert.That(message).IsNull();
        await Assert.That(direct).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(proxied).IsEqualTo(HttpStatusCode.InternalServerError);
    }

    [Test]
    public async Task Own_keys_are_served_through_a_proxy_in_development()
    {
        HttpStatusCode? proxied = null;

        var message = await StartAsync("none", Environments.Development, whileRunning: async app =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/ping");
            request.Headers.Add("X-Forwarded-For", "203.0.113.7");
            proxied = (await app.GetTestClient().SendAsync(request)).StatusCode;
        });

        await Assert.That(message).IsNull();
        await Assert.That(proxied).IsEqualTo(HttpStatusCode.OK);
    }

    private static async Task<string?> StartAsync(string which, string environment, string? url = null, Func<WebApplication, Task>? whileRunning = null)
    {
        var sample = JsonDocument.Parse(await File.ReadAllTextAsync(SampleSettingsPath())).RootElement;
        var local = sample.GetProperty("LocalLogin");

        var settings = new Dictionary<string, string?>
        {
            ["Oidc:ClientId"] = "toamaisutaa-tests",
            ["LocalLogin:Issuer"] = "toamaisutaa-tests",
        };

        switch (which)
        {
            case "signing":
                settings["LocalLogin:SigningKeys:0:Kid"] = "renamed-but-the-same-key";
                settings["LocalLogin:SigningKeys:0:Pem"] = local.GetProperty("SigningKeys")[0].GetProperty("Pem").GetString();
                break;
            case "pepper":
                settings["LocalLogin:Pepper"] = local.GetProperty("Pepper").GetString();
                break;
            case "none":
                settings["LocalLogin:SigningKey"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
                break;
            default:
                settings["TwoFactor:EncryptionKey"] = sample.GetProperty("TwoFactor").GetProperty("EncryptionKey").GetString();
                break;
        }

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = environment });
        if (url is null)
            builder.WebHost.UseTestServer();
        else
            builder.WebHost.UseUrls(url);
        builder.Logging.SetMinimumLevel(LogLevel.None);
        builder.Configuration.AddInMemoryCollection(settings);

        builder.Services.AddToamaisutaaBearer(builder.Configuration);
        builder.Services.Configure<ToamaisutaaLocalLoginOptions>(builder.Configuration.GetSection("LocalLogin"));
        builder.Services.Configure<ToamaisutaaTwoFactorOptions>(builder.Configuration.GetSection("TwoFactor"));

        var app = builder.Build();
        app.MapGet("/ping", () => "pong");

        try
        {
            await app.StartAsync();

            if (whileRunning is not null)
                await whileRunning(app);

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

    private static string SampleSettingsPath()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "samples", "MinimalApiSample", "appsettings.Development.json");

            if (File.Exists(candidate))
                return candidate;
        }

        throw new FileNotFoundException("The sample's appsettings.Development.json was not found above the test output.");
    }
}
