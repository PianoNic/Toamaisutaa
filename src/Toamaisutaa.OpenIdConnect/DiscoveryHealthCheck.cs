using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.OpenIdConnect;

/// <summary>
/// A singleton, because the last successful fetch must outlive a probe: a handler that loaded the
/// document keeps validating after a failed refresh, which is degraded rather than unhealthy.
/// </summary>
/// <remarks>
/// Messages describe only what this check fetched, never what the bearer handler holds, which is
/// loaded lazily and invisible from here.
/// </remarks>
internal sealed class DiscoveryHealthCheck(
    IOptions<ToamaisutaaOidcOptions> options,
    IHttpClientFactory httpClientFactory,
    TimeProvider time) : IHealthCheck
{
    private volatile Fetch? _lastSuccess;

    /// <summary>Cached like a success so a failing issuer is not hit by every probe.</summary>
    private volatile Failure? _lastFailure;

    /// <summary>One shared probe, run to the end whoever stops waiting, so a cancelled caller cannot
    /// prevent its result being cached.</summary>
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
            if (_probe is null || _probe.IsCompleted)
                _probe = ProbeAndRememberAsync(address, settings);

            probe = _probe;
        }

        return await probe.WaitAsync(cancellationToken);
    }

    /// <summary>Takes no caller token on purpose: bounded only by <c>Oidc:HealthCheck:Timeout</c>.</summary>
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
    /// Cached so readiness probes across every replica do not all land on the issuer.
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

            // A proxy that has lost its route can answer 200 with a sign-in page.
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
