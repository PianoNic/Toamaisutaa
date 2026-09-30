using System.Diagnostics.Metrics;

namespace Toamaisutaa.Core.Tests;

internal readonly record struct RecordedMeasurement(string Instrument, double Value, IReadOnlyDictionary<string, string?> Tags)
{
    internal string? Tag(string name) => Tags.TryGetValue(name, out var value) ? value : null;
}

/// <summary>
/// Bound to the meter instance rather than its name, because every harness creates a meter called
/// <c>Toamaisutaa</c> and filtering by name would count whatever else was running.
/// </summary>
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
