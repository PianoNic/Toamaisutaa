using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// Fetches the discovery document the bearer handler validates against, so a wrong
/// <c>Oidc:Authority</c> or an unreachable <c>Oidc:InternalAuthority</c> fails a probe at deploy
/// time instead of answering 401 on every request afterwards.
/// </summary>
/// <remarks>
/// <para>
/// A singleton, because the last successful fetch has to outlive a single probe. A handler that has
/// loaded the document keeps validating tokens against it when a refresh fails, so "this process
/// fetched it minutes ago" is a different answer from "it was never reached at all" - the first is
/// degraded, the second cannot be anything but unhealthy. Telling those apart is why this holds
/// state, and <c>Oidc:HealthCheck:DegradedFor</c> is what stops the first answer outliving its own
/// evidence.
/// </para>
/// <para>
/// What is reported is what this check fetched, never what the bearer handler holds. The handler's
/// document lives in <c>JwtBearerOptions.ConfigurationManager</c>, on its own refresh interval, and
/// is loaded lazily on the first request carrying a token - so a process that has only served
/// anonymous traffic has none. Nothing here can see it, and a message that claimed to would be
/// read at 2am as fact.
/// </para>
/// <para>
/// A plaintext metadata address under <c>Oidc:RequireHttpsMetadata</c> is deliberately not reported
/// here. JwtBearer refuses one while it is building the handler's options, which happens before any
/// request reaches an endpoint, so the process already answers 500 everywhere and this check never
/// gets asked.
/// </para>
/// </remarks>
internal sealed class DiscoveryHealthCheck(
    IOptions<ToamaisutaaOidcOptions> options,
    IHttpClientFactory httpClientFactory,
    TimeProvider time) : IHealthCheck
{
    private volatile Fetch? _lastSuccess;

    /// <summary>The last failed probe, answered from until it is as old as a success would be. The
    /// endpoint is anonymous, and without this every probe while the issuer was failing went out to
    /// it again - the moment it could least take the traffic.</summary>
    private volatile Failure? _lastFailure;

    /// <summary>One probe at a time, shared. The ones that arrive while it runs wait for its answer
    /// instead of each sending their own, and it runs to the end whoever stops waiting - a caller
    /// that gave up used to take the probe down with it, so nothing was cached and the next probe
    /// asked again.</summary>
    private readonly Lock _gate = new();
    private Task<HealthCheckResult>? _probe;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var settings = options.Value;
        var address = DiscoveryAddress.For(settings);

        if (address is null)
        {
            return HealthCheckResult.Unhealthy(
                "No issuer is configured: Oidc:Authority and Oidc:InternalAuthority are both empty, so there is no "
                + "discovery document to fetch. Set Oidc:Authority, or drop AddToamaisutaaHealthChecks() if this "
                + "application only validates the tokens it issues itself.");
        }

        var now = time.GetUtcNow();

        if (Answered(address, settings, now) is { } answered)
            return answered;

        Task<HealthCheckResult> probe;

        lock (_gate)
        {
            // A finished probe stands for as long as Answered says it does, so one that has finished
            // here is one whose answer has run out.
            if (_probe is null || _probe.IsCompleted)
                _probe = ProbeAndRememberAsync(address, settings);

            probe = _probe;
        }

        return await probe.WaitAsync(cancellationToken);
    }

    /// <summary>Bounded by <c>Oidc:HealthCheck:Timeout</c> and by nothing a caller holds.</summary>
    private async Task<HealthCheckResult> ProbeAndRememberAsync(string address, ToamaisutaaOidcOptions settings)
    {
        var now = time.GetUtcNow();
        var (issuer, failure) = await ProbeAsync(address, settings.HealthCheck.Timeout);

        if (issuer is not null)
        {
            var fetched = new Fetch(now, issuer);
            _lastSuccess = fetched;
            _lastFailure = null;
            return Reachable(address, fetched, now);
        }

        _lastFailure = new Failure(now, failure!);
        return Unreachable(address, settings, _lastSuccess, failure!, now);
    }

    /// <summary>
    /// The last result, when it is recent enough to stand. A readiness probe runs every few seconds
    /// across every replica, and the issuer would otherwise carry all of it - succeeding or not.
    /// </summary>
    private HealthCheckResult? Answered(string address, ToamaisutaaOidcOptions settings, DateTimeOffset now)
    {
        var cached = _lastSuccess;

        if (cached is not null && now - cached.At < settings.HealthCheck.RefreshInterval)
            return Reachable(address, cached, now);

        if (_lastFailure is { } failed && now - failed.At < settings.HealthCheck.RefreshInterval)
            return Unreachable(address, settings, cached, failed.Reason, now);

        return null;
    }

    private static HealthCheckResult Unreachable(
        string address,
        ToamaisutaaOidcOptions settings,
        Fetch? cached,
        string failure,
        DateTimeOffset now)
    {
        if (cached is null)
        {
            return HealthCheckResult.Unhealthy(
                $"Could not reach {address}: {failure}. No discovery document has ever been fetched, so no token from "
                + "this issuer can be validated.",
                data: Data(address, null));
        }

        var age = now - cached.At;

        if (age >= settings.HealthCheck.DegradedFor)
        {
            return HealthCheckResult.Unhealthy(
                $"Could not reach {address}: {failure}. This process last fetched the document {Elapsed(age)} ago, "
                + $"past the {settings.HealthCheck.DegradedFor} in Oidc:HealthCheck:DegradedFor, so the issuer has "
                + "been unreachable long enough that a handler here cannot be assumed to still validate tokens.",
                data: Data(address, cached));
        }

        return HealthCheckResult.Degraded(
            $"Could not reach {address}: {failure}. This process last fetched the document {Elapsed(age)} ago, past "
            + $"the {settings.HealthCheck.RefreshInterval} refresh interval, so a handler that loaded it keeps "
            + $"validating tokens until the issuer rotates its signing keys. Unhealthy once that fetch is "
            + $"{settings.HealthCheck.DegradedFor} old.",
            data: Data(address, cached));
    }

    private async Task<(string? Issuer, string? Failure)> ProbeAsync(string address, TimeSpan timeout)
    {
        using var deadline = new CancellationTokenSource(timeout);

        try
        {
            var http = httpClientFactory.CreateClient(ToamaisutaaDefaults.DiscoveryHttpClientName);

            using var response = await http.GetAsync(address, deadline.Token);

            if (!response.IsSuccessStatusCode)
                return (null, $"it answered {(int)response.StatusCode}");

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));

            var issuer = Text(document.RootElement, "issuer");

            // A 200 is not a discovery document. A proxy that has lost its route answers the sign-in
            // page with one, and the handler needs the keys rather than the status.
            if (issuer is null || Text(document.RootElement, "jwks_uri") is null)
                return (null, "it answered 200 without an 'issuer' and 'jwks_uri' pair, so that is not a discovery document");

            return (issuer, null);
        }
        catch (OperationCanceledException)
        {
            return (null, $"no answer within {timeout}");
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            return (null, exception.Message.TrimEnd('.'));
        }
    }

    private static HealthCheckResult Reachable(string address, Fetch fetch, DateTimeOffset now)
    {
        var age = now - fetch.At;

        return HealthCheckResult.Healthy(
            age > TimeSpan.Zero
                ? $"{address} answered for issuer '{fetch.Issuer}' {Elapsed(age)} ago."
                : $"{address} answered for issuer '{fetch.Issuer}'.",
            Data(address, fetch));
    }

    private static IReadOnlyDictionary<string, object> Data(string address, Fetch? fetch)
    {
        var data = new Dictionary<string, object>(StringComparer.Ordinal) { ["address"] = address };

        if (fetch is not null)
        {
            data["issuer"] = fetch.Issuer;
            data["fetchedAt"] = fetch.At;
        }

        return data;
    }

    /// <summary>Whole units. A health report is read in a hurry, and ticks are noise there.</summary>
    private static string Elapsed(TimeSpan span) => span.TotalHours >= 1
        ? $"{(int)span.TotalHours}h{span.Minutes:D2}m"
        : span.TotalMinutes >= 1
            ? $"{(int)span.TotalMinutes}m{span.Seconds:D2}s"
            : $"{(int)span.TotalSeconds}s";

    private static string? Text(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var text = value.GetString();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private sealed record Fetch(DateTimeOffset At, string Issuer);

    private sealed record Failure(DateTimeOffset At, string Reason);
}
