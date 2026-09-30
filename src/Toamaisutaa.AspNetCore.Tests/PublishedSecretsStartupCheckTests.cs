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
/// The sample's keys are in a public repository. Every other startup check passed them, being the
/// right length and valid base64, so a deployment running on a copy of the sample's Development
/// settings signed tokens anyone could forge.
/// </summary>
/// <remarks>Read from the sample's own file, so the test follows the sample if its keys change and
/// the values are not published a second time here.</remarks>
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

    /// <summary>The sample itself has to keep running, which is the reason the values exist.</summary>
    [Test]
    public async Task Starts_in_development_on_the_samples_values()
    {
        await Assert.That(await StartAsync("signing", Environments.Development)).IsNull();
    }

    /// <summary>
    /// Development accepted them on any address, so a container or a staging box started with the
    /// wrong environment and bound to every interface signed tokens anyone could forge. On a real
    /// server, so there are real addresses to judge.
    /// </summary>
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

    private static async Task<string?> StartAsync(string which, string environment, string? url = null)
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
