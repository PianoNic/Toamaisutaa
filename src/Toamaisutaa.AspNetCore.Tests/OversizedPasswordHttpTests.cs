using System.Net;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>Every byte of a password is hashed, so what reaches the hasher is bounded three ways.</summary>
public class OversizedPasswordHttpTests
{
    private static readonly string Huge = new('x', 100_000);

    [Test]
    public async Task Sign_in_refuses_a_password_longer_than_any_that_can_be_set_without_hashing_it()
    {
        var spy = new LongestPasswordHasher();
        await using var app = await TestApp.StartAsync(configureServices: spy.Register);
        var account = await Account.RegisterAsync(app);
        spy.Longest = 0;

        var known = await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = Huge });
        var unknown = await app.Client.PostJson("/auth/login", new { identifier = "nobody", password = Huge });

        await Assert.That(known.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(spy.Longest).IsLessThanOrEqualTo(128);
    }

    [Test]
    public async Task A_current_password_that_long_is_refused_without_hashing_it()
    {
        var spy = new LongestPasswordHasher();
        await using var app = await TestApp.StartAsync(configureServices: spy.Register);
        var account = await Account.RegisterAsync(app);
        spy.Longest = 0;

        var change = await app.Client.PostJson("/auth/password", new { currentPassword = Huge, newPassword = "a whole new passphrase" }, account.AccessToken);

        await Assert.That(change.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(spy.Longest).IsLessThanOrEqualTo(128);
    }

    /// <summary>
    /// The test server does not enforce a body limit, so this checks what is ours: every endpoint
    /// carries the configured one, which Kestrel enforces before the body is read.
    /// </summary>
    [Test]
    public async Task Every_endpoint_the_package_maps_carries_the_body_limit()
    {
        await using var app = await TestApp.StartAsync(configure: settings => settings["LocalLogin:MaxRequestBodyBytes"] = "1024");

        var packageEndpoints = app.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?.StartsWith("/auth", StringComparison.Ordinal) == true)
            .ToList();

        var limits = packageEndpoints.Select(endpoint => endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize).ToList();

        await Assert.That(packageEndpoints.Count).IsGreaterThan(20);
        await Assert.That(limits.Distinct()).IsEquivalentTo(new long?[] { 1024 });
    }

    [Test]
    public async Task Checks_past_the_process_wide_limit_are_answered_503()
    {
        var hasher = new HeldHasher();
        await using var app = await TestApp.StartAsync(
            configure: settings =>
            {
                settings["LocalLogin:RateLimit:MaxConcurrentChecks"] = "1";
                settings["LocalLogin:RateLimit:MaxQueuedChecks"] = "0";
            },
            configureServices: hasher.Register);

        var account = await Account.RegisterAsync(app);
        hasher.Hold = account.Password;

        var held = account.LoginAsync();
        await hasher.Entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        var second = await app.Client.PostJson("/auth/login", new { identifier = "nobody", password = "whatever" });

        hasher.Let();
        await held;

        await Assert.That(second.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
    }

    private sealed class LongestPasswordHasher : IPasswordHasher
    {
        private IPasswordHasher _inner = null!;

        public volatile int Longest;

        public void Register(IServiceCollection services) =>
            services.AddSingleton<IPasswordHasher>(provider =>
            {
                _inner = new Pbkdf2PasswordHasher(provider.GetRequiredService<IOptions<ToamaisutaaLocalLoginOptions>>());
                return this;
            });

        public string Hash(string password)
        {
            Record(password);
            return _inner.Hash(password);
        }

        public PasswordVerificationResult Verify(string password, string hash)
        {
            Record(password);
            return _inner.Verify(password, hash);
        }

        private void Record(string password)
        {
            if (password.Length > Longest)
                Longest = password.Length;
        }
    }
}
