using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The anonymous endpoint an SPA reads its OIDC settings from, and the Host header it falls back on.
/// </summary>
public class ClientConfigurationHttpTests
{
    // Written out: it is the route a consumer's SPA fetches, and a test that read it from the
    // package would agree with a rename.
    private const string Path = "/api/app";

    /// <summary>
    /// With no public URL configured the redirect URI comes from the request's Host header. Cached
    /// by something shared that ignores Host, one forged header would send every SPA loading it to
    /// the attacker's address to sign in.
    /// </summary>
    [Test]
    public async Task The_configuration_is_never_stored_by_a_cache()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.Get(Path);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(response.Headers.CacheControl?.NoStore).IsTrue();
    }

    /// <summary>The endpoint getting-started tells consumers to write, copied as it is there. The
    /// header used to live on the mapped route alone, so this one carried a Host-derived redirect
    /// URI that any shared cache was free to keep.</summary>
    [Test]
    public async Task An_endpoint_of_your_own_built_on_the_provider_is_never_stored_by_a_cache_either()
    {
        await using var app = await TestApp.StartAsync(endpoints =>
            endpoints.MapGet("/api/own", (HttpContext context, IToamaisutaaClientConfigurationProvider provider) =>
                Results.Ok(new { Auth = provider.GetConfiguration(context), FeatureFlags = "none" }))
                .AllowAnonymous());

        var response = await app.Client.Get("/api/own");

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(response.Headers.CacheControl?.NoStore).IsTrue();
    }

    [Test]
    public async Task Falling_back_to_the_host_header_outside_development_is_warned_about()
    {
        var warnings = new ConcurrentQueue<string>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddSingleton<ILoggerProvider>(new WarningCollector(warnings)));

        await app.Client.Get(Path);
        await app.Client.Get(Path);

        await Assert.That(warnings.Count(message => message.Contains("Oidc:PublicUrl"))).IsEqualTo(1);
    }

    [Test]
    public async Task A_configured_public_url_is_not_warned_about()
    {
        var warnings = new ConcurrentQueue<string>();

        await using var app = await TestApp.StartAsync(
            configure: settings => settings["Oidc:PublicUrl"] = "https://app.example.com",
            configureServices: services => services.AddSingleton<ILoggerProvider>(new WarningCollector(warnings)));

        var body = await (await app.Client.Get(Path)).Json();

        await Assert.That(warnings.Count(message => message.Contains("Oidc:PublicUrl"))).IsEqualTo(0);
        await Assert.That(body.String("redirectUri")).IsEqualTo("https://app.example.com/");
    }

    private sealed class WarningCollector(ConcurrentQueue<string> warnings) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Collector(warnings);

        public void Dispose()
        {
        }

        private sealed class Collector(ConcurrentQueue<string> warnings) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel))
                    warnings.Enqueue(formatter(state, exception));
            }
        }
    }
}
