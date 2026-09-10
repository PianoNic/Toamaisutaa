using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
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

    /// <summary>
    /// An application registers an <c>IDistributedCache</c> for its own reasons. That is not a
    /// statement that this package may keep the claims it decides authorization on in it, so
    /// nothing goes near it until the option says so.
    /// </summary>
    [Test]
    public async Task Claims_never_reach_a_distributed_cache_by_default()
    {
        var userInfo = new CountingUserInfo(RolesBody);
        userInfo.Release.SetResult();

        var shared = new RecordingDistributedCache();
        var enricher = Enricher(userInfo, shared);

        await enricher.EnrichAsync(Context("sub-1"));

        // The write does not have to finish before the caller does, so give it the chance to
        // happen rather than passing on timing.
        await Task.Delay(250);

        // HybridCache reads a housekeeping key of its own out of L2 whatever the entry flags say.
        // What must not be there is this package's entry.
        await Assert.That(shared.Reads.Where(Ours)).IsEmpty();
        await Assert.That(shared.Writes.Where(Ours)).IsEmpty();
    }

    [Test]
    public async Task Opting_in_serves_a_second_instance_without_calling_userinfo()
    {
        var shared = new RecordingDistributedCache();

        var first = new CountingUserInfo(RolesBody);
        first.Release.SetResult();
        await Enricher(first, shared, Sharing("admin-api")).EnrichAsync(Context("sub-1"));

        await WaitUntil(() => shared.Writes.Any(Ours));

        var second = new CountingUserInfo(RolesBody);
        second.Release.SetResult();
        var context = Context("sub-1");

        // A second instance: its own HybridCache, so its own empty first level, and only the shared
        // store between them.
        await Enricher(second, shared, Sharing("admin-api")).EnrichAsync(context);

        await Assert.That(second.Calls).IsEqualTo(0);
        await Assert.That(Roles(context)).IsEquivalentTo(new[] { "admin", "staff" });
    }

    /// <summary>
    /// What the key has to name. An admin API and a public API against one issuer, sharing one
    /// Redis, hold different audiences and therefore see different claims for one subject. The
    /// scheme name is "Bearer" in both, so a key of scheme and subject alone would let whichever
    /// fetched first decide for the other.
    /// </summary>
    [Test]
    public async Task Two_audiences_against_one_issuer_do_not_share_an_entry()
    {
        var shared = new RecordingDistributedCache();

        var admin = new CountingUserInfo(RolesBody);
        admin.Release.SetResult();
        await Enricher(admin, shared, Sharing("admin-api")).EnrichAsync(Context("sub-1"));

        await WaitUntil(() => shared.Writes.Any(Ours));

        var other = new CountingUserInfo("""{"roles":["staff"]}""");
        other.Release.SetResult();
        var context = Context("sub-1");

        await Enricher(other, shared, Sharing("public-api")).EnrichAsync(context);

        await Assert.That(other.Calls).IsEqualTo(1);
        await Assert.That(Roles(context)).IsEquivalentTo(new[] { "staff" });
    }

    private static UserInfoClaimsEnricher Enricher(
        HttpMessageHandler handler,
        IDistributedCache? distributed = null,
        ToamaisutaaOidcOptions? settings = null)
    {
        var services = new ServiceCollection();

        if (distributed is not null)
            services.AddSingleton(distributed);

        var cache = services
            .AddHybridCache()
            .Services
            .BuildServiceProvider()
            .GetRequiredService<HybridCache>();

        return new UserInfoClaimsEnricher(
            Options.Create(settings ?? new ToamaisutaaOidcOptions()),
            new OneHandlerFactory(handler),
            cache,
            NullLoggerFactory.Instance);
    }

    /// <summary>Keys this package wrote, as opposed to HybridCache's own.</summary>
    private static bool Ours(string key) => key.StartsWith("toamaisutaa:userinfo:", StringComparison.Ordinal);

    /// <summary>A service that has opted into the shared cache, identified the way a deployment
    /// is: by issuer and by the audience it accepts.</summary>
    private static ToamaisutaaOidcOptions Sharing(string audience) => new()
    {
        Authority = "https://issuer.test",
        ClientId = audience,
        ShareUserInfoCacheAcrossInstances = true,
    };

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

    /// <summary>
    /// The consumer's own distributed cache, and a record of what this package did to it.
    /// </summary>
    /// <remarks>
    /// A dictionary rather than <c>AddDistributedMemoryCache()</c>: HybridCache recognises
    /// <c>MemoryDistributedCache</c> as its own first level in other clothes and declines to use it
    /// as a second one, so that arrangement records nothing and proves nothing.
    /// </remarks>
    private sealed class RecordingDistributedCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _entries = new(StringComparer.Ordinal);
        private readonly ConcurrentQueue<string> _reads = new();
        private readonly ConcurrentQueue<string> _writes = new();

        public IReadOnlyCollection<string> Reads => _reads;

        public IReadOnlyCollection<string> Writes => _writes;

        public byte[]? Get(string key)
        {
            _reads.Enqueue(key);

            return _entries.TryGetValue(key, out var value) ? value : null;
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) =>
            Task.FromResult(Get(key));

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            _writes.Enqueue(key);
            _entries[key] = value;
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);

            return Task.CompletedTask;
        }

        public void Refresh(string key)
        {
        }

        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key) => _entries.TryRemove(key, out _);

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);

            return Task.CompletedTask;
        }
    }

    private sealed class UnreachableUserInfo : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("No such host is known.");
    }
}
