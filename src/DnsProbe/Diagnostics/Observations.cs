using System.Globalization;
using DnsProbe.Dns;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Looks for things in a response that are worth pointing out but are not errors.
///
/// Everything here is a heuristic, and the wording is deliberately cautious: these are
/// observations that suggest where to look next, not verdicts. A diagnostic tool that overstates
/// its conclusions is worse than one that stays quiet, because the user acts on what it says.
/// </summary>
public static class Observations
{
    /// <summary>Observations that can be made from a single response.</summary>
    public static IReadOnlyList<string> ForAttempt(DnsQueryAttempt attempt, ProbeContext context)
    {
        var notes = new List<string>();

        if (!attempt.IsSuccess || attempt.Response is null)
        {
            return notes;
        }

        DnsMessage response = attempt.Response;
        bool ednsRequested = context.Edns is { Enabled: true };

        // RFC 6891 requires an EDNS aware server to echo an OPT record. Missing it means either
        // the server predates EDNS, or something rewrote the response on the way back.
        if (ednsRequested && response.Edns is null)
        {
            notes.Add(
                "An EDNS(0) OPT record was sent but the response carried none. A server that supports "
                + "EDNS is required to echo one, so either this server is old, or something between "
                + "you and it rewrote the response. Compare with --tcp and with a different server.");
        }

        // A server that accepted a large payload size should not need to truncate.
        if (ednsRequested
            && response.Header.Truncated
            && response.Edns is EdnsResponse edns
            && edns.UdpPayloadSize >= context.Edns!.UdpPayloadSize)
        {
            notes.Add(
                $"The answer was truncated even though the server advertised {edns.UdpPayloadSize} bytes "
                + "of UDP payload. Something on the path may be limiting the datagram size.");
        }

        // The server advertising far more than we can accept is worth knowing about: large UDP
        // answers are the ones most likely to be fragmented and dropped.
        if (response.Edns is EdnsResponse serverEdns
            && ednsRequested
            && serverEdns.UdpPayloadSize > 1500)
        {
            notes.Add(
                $"The server advertises a {serverEdns.UdpPayloadSize} byte UDP payload. Answers that "
                + "large are fragmented on most links, which is a common source of intermittent "
                + "DNS failures.");
        }

        if (response.Header is { RecursionDesired: true, RecursionAvailable: false })
        {
            notes.Add(
                "Recursion was requested but the server says it is not available (ra=0). This server "
                + "only answers for zones it is authoritative for.");
        }

        return notes;
    }

    /// <summary>The shortest window over which a frozen TTL means anything.</summary>
    private const double MinimumWindowSeconds = 5;

    /// <summary>
    /// Observations that only become visible across repeated queries. The TTL check is the useful
    /// one: a caching resolver counts its TTL down, so a value that never moves means the answer
    /// is not coming from a normal cache.
    /// </summary>
    /// <param name="firstAnswerTtls">TTL of the first answer record, one entry per query.</param>
    /// <param name="intervalMilliseconds">Delay between queries.</param>
    /// <param name="anyAuthoritative">
    /// True when any response had aa=1. An authoritative server serves the TTL straight from its
    /// zone file and never counts it down, so the check does not apply and would only produce a
    /// false alarm.
    /// </param>
    public static IReadOnlyList<string> ForRepeatedQueries(
        IReadOnlyList<uint> firstAnswerTtls,
        int intervalMilliseconds,
        bool anyAuthoritative)
    {
        var notes = new List<string>();

        if (anyAuthoritative)
        {
            return notes;
        }

        if (firstAnswerTtls.Count < 3 || intervalMilliseconds < 500)
        {
            return notes;
        }

        uint first = firstAnswerTtls[0];
        bool allIdentical = true;
        bool anyDecrease = false;

        for (int i = 1; i < firstAnswerTtls.Count; i++)
        {
            if (firstAnswerTtls[i] != first)
            {
                allIdentical = false;
            }

            if (firstAnswerTtls[i] < firstAnswerTtls[i - 1])
            {
                anyDecrease = true;
            }
        }

        double elapsedSeconds = (firstAnswerTtls.Count - 1) * intervalMilliseconds / 1000.0;

        if (allIdentical && first > 0 && elapsedSeconds < MinimumWindowSeconds)
        {
            notes.Add(
                "The TTL did not change, but the queries only spanned a few seconds, which is too "
                + "short to conclude anything. Repeat with --count 10 --interval 2000 to see whether "
                + "it counts down.");
            return notes;
        }

        if (allIdentical && first > 0)
        {
            // Note: an interpolated string that is built by concatenation no longer binds to the
            // string.Create handler overload, so the values are formatted explicitly instead.
            string ttlText = first.ToString(CultureInfo.InvariantCulture);
            string countText = firstAnswerTtls.Count.ToString(CultureInfo.InvariantCulture);
            string secondsText = elapsedSeconds.ToString("0", CultureInfo.InvariantCulture);

            notes.Add(
                $"The TTL stayed at {ttlText} across {countText} queries spanning about "
                + $"{secondsText} seconds, even though the server did not claim to be authoritative "
                + "(aa=0). A caching resolver counts its TTL down, so a value that never moves "
                + "suggests the answer is generated rather than served from a real cache.");
        }
        else if (anyDecrease)
        {
            notes.Add("The TTL counts down between queries, which is what a normal caching resolver does.");
        }

        return notes;
    }
}
