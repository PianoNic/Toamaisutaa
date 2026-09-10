using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// An audit sink registered the way a consumer registers one, behind the whole pipeline.
/// </summary>
/// <remarks>
/// The service suite proves the events are published; nothing there proves a sink resolved out of
/// the application's own container ever runs, or that one which throws leaves the response alone.
/// Both of those live between a correct service and the wire, which is where this suite exists.
/// </remarks>
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

        // The session the token names, so an audit row and a revocation later line up.
        var session = Account.DecodeClaims((await response.Json()).String("access_token")!).String("toa_sid");

        await Assert.That(signIns[^1].SessionId.ToString()).IsEqualTo(session);
    }

    /// <summary>
    /// The endpoints collapse every sign-in failure into one 401 so a caller cannot tell an unknown
    /// account from a wrong password. A sink is on the inside of that and gets the real reason.
    /// </summary>
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

    /// <summary>
    /// The promise the feature rests on, asserted where it matters: a sink whose storage is down
    /// must not turn a correct sign-in into a 500, or into anything but the pair it was going to
    /// return anyway.
    /// </summary>
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

    /// <summary>Every sink is called, and one failing does not cost the others their events.</summary>
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

    /// <summary>Scoped, so a sink can take the same unit of work the request is already using -
    /// which is only true if it is resolved per request rather than once.</summary>
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
}
