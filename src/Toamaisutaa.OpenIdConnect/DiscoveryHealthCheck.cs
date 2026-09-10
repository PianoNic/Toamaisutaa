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
/// A singleton, because the last successful fetch has to outlive a single probe. The handler keeps
/// serving a cached document when a refresh fails, so "cached, and older than the refresh interval"
/// is a different answer from "never reached at all" - the first is degraded and still validating
/// tokens, the second cannot validate anything. Telling those apart is the reason this holds state.
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
        var cached = _lastSuccess;

        // Answered from the last result in between, because a readiness probe runs every few
        // seconds across every replica and the issuer would carry all of it.
        if (cached is not null && now - cached.At < settings.HealthCheck.RefreshInterval)
            return Reachable(address, cached, now);

        var (issuer, failure) = await ProbeAsync(address, settings.HealthCheck.Timeout, cancellationToken);

        if (issuer is not null)
        {
            var fetched = new Fetch(now, issuer);
            _lastSuccess = fetched;
            return Reachable(address, fetched, now);
        }

        if (cached is null)
        {
            return HealthCheckResult.Unhealthy(
                $"Could not reach {address}: {failure}. No discovery document has ever been fetched, so no token from "
                + "this issuer can be validated.",
                data: Data(address, null));
        }

        return HealthCheckResult.Degraded(
            $"Could not reach {address}: {failure}. The bearer handler is still serving the document fetched "
            + $"{Elapsed(now - cached.At)} ago, past the {settings.HealthCheck.RefreshInterval} refresh interval, so "
            + "tokens keep validating until the issuer rotates its signing keys.",
            data: Data(address, cached));
    }

    /// <summary>
    /// Everything that is not a fetch failure is left to the caller: an <see cref="OperationCanceledException"/>
    /// from the probe's own token means the health report was abandoned, not that the issuer is
    /// down, and reporting it as unhealthy would be a lie told at shutdown.
    /// </summary>
    private async Task<(string? Issuer, string? Failure)> ProbeAsync(
        string address,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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
}
