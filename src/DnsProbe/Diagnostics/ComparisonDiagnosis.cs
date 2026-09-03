using System.Net;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Turns a set of per-interface results into the one sentence the user actually wants.
///
/// Nothing here is guessed. Every conclusion follows from results the tool measured itself: if
/// one interface reached the server and another did not, the server is demonstrably up and the
/// problem is demonstrably path-specific. That is a deduction, not a hypothesis, which is why
/// this exists and a list of "likely causes" does not.
/// </summary>
public static class ComparisonDiagnosis
{
    public static IReadOnlyList<string> Diagnose(IReadOnlyList<ComparisonRow> rows, IPEndPoint server)
    {
        var lines = new List<string>();

        if (rows.Count < 2)
        {
            // With a single path there is nothing to compare, so there is nothing to deduce.
            return lines;
        }

        var succeeded = new List<ComparisonRow>();
        var failed = new List<ComparisonRow>();

        foreach (ComparisonRow row in rows)
        {
            if (string.Equals(row.Result, "SUCCESS", StringComparison.Ordinal))
            {
                succeeded.Add(row);
            }
            else
            {
                failed.Add(row);
            }
        }

        if (succeeded.Count == 0)
        {
            lines.Add($"No interface reached {server.Address}. Because every path failed, this does "
                      + "not distinguish between the server being down and the destination being "
                      + "blocked for this host. Test the same server from a different machine.");

            if (AllSameResult(failed, out string? sharedResult))
            {
                lines.Add($"Every interface failed the same way ({sharedResult}), which points at "
                          + "the destination rather than at any one path.");
            }

            return lines;
        }

        if (failed.Count == 0)
        {
            lines.Add($"Every interface reached {server.Address}. DNS resolution is not path-specific "
                      + "on this host.");
            return lines;
        }

        // The interesting case: some paths work and some do not.
        lines.Add($"{server.Address} is reachable: {Names(succeeded)} got an answer. "
                  + $"The failure on {Names(failed)} is therefore specific to that path, not to the "
                  + "DNS server.");

        var refused = new List<ComparisonRow>();
        var unreachable = new List<ComparisonRow>();
        var silent = new List<ComparisonRow>();

        foreach (ComparisonRow row in failed)
        {
            switch (row.Result)
            {
                case "REFUSED":
                    refused.Add(row);
                    break;

                case "NET-UNREACH":
                case "HOST-UNREACH":
                case "IF-UNREACH":
                    unreachable.Add(row);
                    break;

                case "TIMEOUT":
                    silent.Add(row);
                    break;
            }
        }

        // Each of these follows from the specific outcome, not from a general guess.
        if (refused.Count > 0)
        {
            lines.Add($"{Names(refused)} reached the server and was refused by it. The server "
                      + "answered, so this is an access rule on the DNS server keyed to the source "
                      + "address, not a network fault.");
        }

        if (unreachable.Count > 0)
        {
            lines.Add($"{Names(unreachable)} had no route to the server, so nothing was ever sent. "
                      + "Run with --route-check on that interface to see the routing decision.");
        }

        if (silent.Count > 0)
        {
            lines.Add($"{Names(silent)} sent the query and heard nothing back. The packet left the "
                      + "host but no reply returned: filtering along the path, or a reply that took "
                      + "a different route home, both look like this. Confirm with a capture.");
        }

        return lines;
    }

    private static bool AllSameResult(IReadOnlyList<ComparisonRow> rows, out string? result)
    {
        result = rows.Count > 0 ? rows[0].Result : null;

        foreach (ComparisonRow row in rows)
        {
            if (!string.Equals(row.Result, result, StringComparison.Ordinal))
            {
                result = null;
                return false;
            }
        }

        return result is not null;
    }

    private static string Names(IReadOnlyList<ComparisonRow> rows)
    {
        var names = new List<string>(rows.Count);

        foreach (ComparisonRow row in rows)
        {
            names.Add(row.InterfaceName);
        }

        return names.Count == 1 ? names[0] : string.Join(", ", names);
    }
}
