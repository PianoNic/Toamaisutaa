using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Toamaisutaa.Abstractions;
using Toamaisutaa.OpenIdConnect;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// How often the userinfo endpoint is actually called, and what happens when it answers badly.
/// </summary>
/// <remarks>
/// Counted at the message handler rather than asserted on the cache, because the cache is the
/// implementation and the call is the thing an issuer's rate limiter sees. A page reload fires a
/// dozen requests carrying one token before any of them has answered, which is the case a plain
/// memory cache is empty for every time.
/// </remarks>
public class UserInfoCacheTests
{
    private const string RolesBody = """{"roles":["admin","staff"]}""";

    [Test]
    public async Task Two_concurrent_enrichments_for_one_subject_call_userinfo_once()
    {
        var userInfo = new CountingUserInfo(RolesBody);
        var enricher = Enricher(userInfo);

        var firstContext = Context("sub-1");
        var first = enricher.EnrichAsync(firstContext);

        // The first call is now inside the handler and cannot answer until the test lets it.
        await WaitUntil(() => userInfo.Calls == 1);

        var secondContext = Context("sub-1");
        var second = enricher.EnrichAsync(secondContext);

        // The whole assertion: a second enrichment arriving before the first has answered joins it.
        // Without stampede protection this is 2 as soon as the second call reaches the handler.
        await Task.Delay(250);
        await Assert.That(userInfo.Calls).IsEqualTo(1);

        userInfo.Release.SetResult();
        await first;
        await second;

        await Assert.That(userInfo.Calls).IsEqualTo(1);
        await Assert.That(Roles(firstContext)).IsEquivalentTo(new[] { "admin", "staff" });
        await Assert.That(Roles(secondContext)).IsEquivalentTo(new[] { "admin", "staff" });
    }

    [Test]
    public async Task A_second_enrichment_for_one_subject_reads_the_cached_claims()
    {
        var userInfo = new CountingUserInfo(RolesBody);
        userInfo.Release.SetResult();

        var enricher = Enricher(userInfo);

        await enricher.EnrichAsync(Context("sub-1"));

        var second = Context("sub-1");
        await enricher.EnrichAsync(second);

        await Assert.That(userInfo.Calls).IsEqualTo(1);
        await Assert.That(Roles(second)).IsEquivalentTo(new[] { "admin", "staff" });
    }

    [Test]
    public async Task Two_subjects_are_cached_apart()
    {
        var userInfo = new CountingUserInfo(RolesBody);
        userInfo.Release.SetResult();

        var enricher = Enricher(userInfo);

        await enricher.EnrichAsync(Context("sub-1"));
        await enricher.EnrichAsync(Context("sub-2"));

        await Assert.That(userInfo.Calls).IsEqualTo(2);
    }

    /// <summary>
    /// The fail-open. A userinfo endpoint that is down decides nothing: the token's own claims do,
    /// and the request is not turned into a 500.
    /// </summary>
    [Test]
    public async Task A_userinfo_endpoint_answering_500_leaves_the_token_claims_deciding()
    {
        var userInfo = new CountingUserInfo(RolesBody) { Status = HttpStatusCode.InternalServerError };
        userInfo.Release.SetResult();

        var enricher = Enricher(userInfo);
        var context = Context("sub-1");

        await enricher.EnrichAsync(context);

        await Assert.That(Roles(context)).IsEmpty();
    }

    /// <summary>
    /// A failed read is not an answer, so it is not stored. Caching the empty claim set a 503
    /// produces would read as "this user has no groups" for the whole UserInfoCacheDuration.
    /// </summary>
    [Test]
    public async Task A_failed_userinfo_read_is_not_cached()
    {
        var userInfo = new CountingUserInfo(RolesBody) { Status = HttpStatusCode.ServiceUnavailable };
        userInfo.Release.SetResult();

        var enricher = Enricher(userInfo);

        await enricher.EnrichAsync(Context("sub-1"));
        await enricher.EnrichAsync(Context("sub-1"));

        await Assert.That(userInfo.Calls).IsEqualTo(2);
    }

    /// <summary>
    /// The other half of the fail-open, and the one that would break silently: an exception raised
    /// inside the cache factory has to reach the handler that swallows it as the type it was
    /// thrown as.
    /// </summary>
    [Test]
    public async Task A_userinfo_endpoint_that_cannot_be_reached_leaves_the_token_claims_deciding()
    {
        var enricher = Enricher(new UnreachableUserInfo());
        var context = Context("sub-1");

        await enricher.EnrichAsync(context);

        await Assert.That(Roles(context)).IsEmpty();
    }

    private static UserInfoClaimsEnricher Enricher(HttpMessageHandler handler)
    {
        var cache = new ServiceCollection()
            .AddHybridCache()
            .Services
            .BuildServiceProvider()
            .GetRequiredService<HybridCache>();

        return new UserInfoClaimsEnricher(
            Options.Create(new ToamaisutaaOidcOptions()),
            new OneHandlerFactory(handler),
            cache,
            NullLoggerFactory.Instance);
    }

    /// <summary>A validated bearer token, reduced to the three things the enricher reads off it:
    /// the subject, the raw token, and where the issuer says userinfo lives.</summary>
    private static TokenValidatedContext Context(string subject)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer token-for-{subject}";

        var options = new JwtBearerOptions
        {
            Configuration = new OpenIdConnectConfiguration { UserInfoEndpoint = "https://issuer.test/userinfo" },
        };

        var scheme = new AuthenticationScheme(
            JwtBearerDefaults.AuthenticationScheme,
            displayName: null,
            handlerType: typeof(JwtBearerHandler));

        return new TokenValidatedContext(httpContext, scheme, options)
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "Test")),
        };
    }

    private static IEnumerable<string> Roles(TokenValidatedContext context) =>
        context.Principal!.FindAll("roles").Select(claim => claim.Value);

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 500 && !condition(); attempt++)
            await Task.Delay(10);

        await Assert.That(condition()).IsTrue();
    }

    private sealed class OneHandlerFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class CountingUserInfo(string body) : HttpMessageHandler
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public HttpStatusCode Status { get; init; } = HttpStatusCode.OK;

        /// <summary>Held closed so a second enrichment can be started while the first is still
        /// waiting, which is the only arrangement that tells stampede protection from a cache hit.
        /// </summary>
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            await Release.Task.WaitAsync(cancellationToken);

            return new HttpResponseMessage(Status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class UnreachableUserInfo : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("No such host is known.");
    }
}
