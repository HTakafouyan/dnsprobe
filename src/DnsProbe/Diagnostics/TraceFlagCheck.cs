using DnsProbe.Dns;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Checks the header flags of a trace response against what that step should have returned.
///
/// A delegation chain has a strict shape, and the flags say whether a server is playing its part.
/// A referral should carry <c>qr</c> alone; an authoritative answer should carry <c>qr aa</c>.
/// Anything else is worth pointing at - most usefully <c>ra</c> on a root or TLD server, which
/// those servers never set because they do not perform recursion. A resolver answering in their
/// place does.
/// </summary>
public static class TraceFlagCheck
{
    /// <summary>
    /// Returns the ways this response departs from what the step should have produced.
    /// An empty list means the flags were exactly as expected.
    /// </summary>
    public static IReadOnlyList<string> Anomalies(TraceStep step)
    {
        var anomalies = new List<string>();

        if (step.Response is not DnsMessage response)
        {
            return anomalies;
        }

        DnsHeader header = response.Header;

        switch (step.Outcome)
        {
            case TraceStepOutcome.Referral:
                // A referral comes from a server that is not authoritative for the queried name,
                // so aa must be clear - and it is delegating, not resolving, so ra must be too.
                if (header.AuthoritativeAnswer)
                {
                    anomalies.Add("aa set on a referral (the server both delegates and claims the zone)");
                }

                if (header.RecursionAvailable)
                {
                    anomalies.Add("ra set (this server offers recursion; a root or TLD server does not)");
                }

                break;

            case TraceStepOutcome.Answer:
                // The end of the chain must be the zone's own server.
                if (!header.AuthoritativeAnswer)
                {
                    anomalies.Add("aa absent (the answer did not come from a server for this zone)");
                }

                if (header.RecursionAvailable && step.Zone == ".")
                {
                    anomalies.Add("ra set on a root server, which never performs recursion");
                }

                break;

            case TraceStepOutcome.NoData:
            case TraceStepOutcome.NameError:
                if (!header.AuthoritativeAnswer)
                {
                    anomalies.Add("aa absent, so this negative answer is not authoritative");
                }

                break;
        }

        if (header.Truncated)
        {
            anomalies.Add("tc set (the response was truncated)");
        }

        return anomalies;
    }

    /// <summary>
    /// True when a step is suspicious enough that the flags should be shown even without
    /// --verbose.
    /// </summary>
    public static bool IsUnexpected(TraceStep step) => Anomalies(step).Count > 0;
}
