using DnsProbe.Dns;

namespace DnsProbe.Diagnostics;

/// <summary>Accumulates round trip times and success/failure counts across repeated queries.</summary>
public sealed class QueryStatistics
{
    private readonly List<double> _roundTripMilliseconds = new();

    public int Sent { get; private set; }

    public int Received { get; private set; }

    public int Lost => Sent - Received;

    public double LossPercentage => Sent == 0 ? 0 : Lost * 100.0 / Sent;

    public double? Minimum => _roundTripMilliseconds.Count == 0 ? null : _roundTripMilliseconds.Min();

    public double? Maximum => _roundTripMilliseconds.Count == 0 ? null : _roundTripMilliseconds.Max();

    public double? Average => _roundTripMilliseconds.Count == 0 ? null : _roundTripMilliseconds.Average();

    /// <summary>Mean absolute deviation from the average - a simple jitter indicator.</summary>
    public double? Jitter
    {
        get
        {
            if (_roundTripMilliseconds.Count < 2)
            {
                return null;
            }

            double average = _roundTripMilliseconds.Average();
            double total = 0;
            foreach (double value in _roundTripMilliseconds)
            {
                total += Math.Abs(value - average);
            }

            return total / _roundTripMilliseconds.Count;
        }
    }

    public void Record(DnsQueryAttempt attempt)
    {
        Sent++;

        if (attempt.IsSuccess)
        {
            Received++;
            _roundTripMilliseconds.Add(attempt.RoundTripTime.TotalMilliseconds);
        }
    }
}
