using System.Diagnostics.Metrics;

namespace Toamaisutaa.Core.Tests;

/// <summary>One measurement as it was published, with the tags flattened to strings.</summary>
internal readonly record struct RecordedMeasurement(string Instrument, double Value, IReadOnlyDictionary<string, string?> Tags)
{
    internal string? Tag(string name) => Tags.TryGetValue(name, out var value) ? value : null;
}

/// <summary>
/// Collects everything a single <see cref="Meter"/> publishes while it is alive.
/// </summary>
/// <remarks>
/// Bound to the meter instance rather than to its name, because every harness in the suite creates
/// a meter called <c>Toamaisutaa</c> and a listener filtering by name would count whatever else was
/// running at the same time - which is the shape of a test that passes for the wrong reason.
/// </remarks>
internal sealed class MeterProbe : IDisposable
{
    private readonly MeterListener _listener = new();
    private readonly List<RecordedMeasurement> _measurements = [];
    private readonly Lock _gate = new();

    internal MeterProbe(Meter meter)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter, meter))
                listener.EnableMeasurementEvents(instrument);
        };

        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Record(instrument, value, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Record(instrument, value, tags));

        _listener.Start();
    }

    internal IReadOnlyList<RecordedMeasurement> All
    {
        get
        {
            lock (_gate)
                return [.. _measurements];
        }
    }

    internal IReadOnlyList<RecordedMeasurement> For(string instrument) =>
        [.. All.Where(measurement => measurement.Instrument == instrument)];

    public void Dispose() => _listener.Dispose();

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var flattened = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var tag in tags)
            flattened[tag.Key] = tag.Value?.ToString();

        lock (_gate)
            _measurements.Add(new RecordedMeasurement(instrument.Name, value, flattened));
    }
}
