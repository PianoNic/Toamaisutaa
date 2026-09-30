using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

public class AuthenticationEventHttpTests
{
    [Test]
    public async Task A_sign_in_reaches_a_sink_registered_the_documented_way()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var account = await Account.RegisterAsync(app);
        var response = await account.LoginAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        var signIns = recorded.OfType<SignInSucceeded>().ToList();

        // Registration signs in as well, so both ceremonies are here.
        await Assert.That(signIns.Count).IsEqualTo(2);
        await Assert.That(signIns[^1].AuthenticationMethods).Contains("pwd");
        await Assert.That(signIns[^1].Kind).IsEqualTo("sign-in-succeeded");

        var session = Account.DecodeClaims((await response.Json()).String("access_token")!).String("toa_sid");

        await Assert.That(signIns[^1].SessionId.ToString()).IsEqualTo(session);
    }

    [Test]
    public async Task A_refused_sign_in_tells_the_sink_more_than_it_tells_the_caller()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var account = await Account.RegisterAsync(app);

        var response = await app.Client.PostJson("/auth/login", new { identifier = account.UserName, password = "not the password" });
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(body.String("error")).IsEqualTo("invalid_grant");

        var failure = recorded.OfType<SignInFailed>().Single();

        await Assert.That(failure.Reason).IsEqualTo(SignInOutcome.InvalidPassword);
        await Assert.That(failure.UserId).IsNotNull();
    }

    [Test]
    public async Task A_sink_that_throws_leaves_the_login_response_untouched()
    {
        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddToamaisutaaAuthenticationEventSink<ThrowingSink>());

        var account = await Account.RegisterAsync(app);
        var response = await account.LoginAsync();
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(body.String("token_type")).IsEqualTo("Bearer");
    }

    /// <summary>HttpClient's own timeout raises TaskCanceledException with no token cancelled, which a
    /// filter reading the exception type rather than the token would turn into a 500.</summary>
    [Test]
    public async Task A_sink_that_times_out_on_its_own_leaves_the_login_response_untouched()
    {
        await using var app = await TestApp.StartAsync(configureServices: services =>
            services.AddToamaisutaaAuthenticationEventSink<TimingOutSink>());

        var account = await Account.RegisterAsync(app);
        var response = await account.LoginAsync();
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(body.String("refresh_token")).IsNotNull();
        await Assert.That(body.String("token_type")).IsEqualTo("Bearer");
    }

    /// <summary>This throws while dependency injection materialises the publisher's dependencies,
    /// before any try block around the sinks is reached.</summary>
    [Test]
    public async Task A_sink_whose_constructor_throws_costs_only_its_own_events()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<UnconstructableSink>();
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        var account = await Account.RegisterAsync(app);
        var response = await account.LoginAsync();
        var body = await response.Json();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body.String("access_token")).IsNotNull();
        await Assert.That(recorded.OfType<SignInSucceeded>()).IsNotEmpty();
    }

    [Test]
    public async Task A_second_sink_still_gets_the_event_after_the_first_one_throws()
    {
        var recorded = new List<AuthenticationEvent>();

        await using var app = await TestApp.StartAsync(configureServices: services =>
        {
            services.AddSingleton(recorded);
            services.AddToamaisutaaAuthenticationEventSink<ThrowingSink>();
            services.AddToamaisutaaAuthenticationEventSink<RecordingSink>();
        });

        await Account.RegisterAsync(app);

        await Assert.That(recorded.OfType<SignInSucceeded>()).IsNotEmpty();
    }

    private sealed class RecordingSink(List<AuthenticationEvent> recorded) : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default)
        {
            recorded.Add(authenticationEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingSink : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("the audit database is unreachable");
    }

    private sealed class TimingOutSink : IAuthenticationEventSink
    {
        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default) =>
            throw new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.");
    }

    private sealed class UnconstructableSink : IAuthenticationEventSink
    {
        public UnconstructableSink() => throw new InvalidOperationException("the audit store has no connection string");

        public Task HandleAsync(AuthenticationEvent authenticationEvent, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
