using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Diagnostics;

/// <summary>How a stage turned out.</summary>
public enum StageResult
{
    /// <summary>The stage was not attempted, because an earlier one failed.</summary>
    Skipped,

    /// <summary>Measured and fine.</summary>
    Ok,

    /// <summary>Measured and it failed. This is where the query stopped.</summary>
    Failed,

    /// <summary>Attempted, but the answer is not conclusive either way.</summary>
    Unknown,
}

/// <summary>
/// One step of the journey a query takes, with a note saying how it was determined.
///
/// The note matters as much as the result. "Socket: OK" on its own invites the reader to believe
/// more was verified than actually was, so every stage records the evidence behind it.
/// </summary>
public sealed class ProbeStage
{
    public required string Name { get; init; }

    public required StageResult Result { get; init; }

    /// <summary>What was actually observed, in a few words.</summary>
    public required string Evidence { get; init; }
}

/// <summary>
/// Builds the stage list for a single attempt.
///
/// Deliberately absent: a "packet transmitted" stage. A successful <c>send()</c> only means the
/// stack accepted the datagram; it does not mean a frame reached the wire. Claiming otherwise
/// would contradict the whole point of this tool, which is that the socket layer and the wire are
/// not the same thing. Only Wireshark can confirm transmission, and the README says so.
/// </summary>
public static class ProbeStages
{
    public static IReadOnlyList<ProbeStage> Build(
        DnsQueryAttempt attempt,
        ProbeContext context,
        RouteInfo? route,
        string? routeError,
        NeighbourInfo? neighbour)
    {
        var stages = new List<ProbeStage>();

        // ---- 1. interface and source selection -----------------------------------
        stages.Add(new ProbeStage
        {
            Name = "Interface",
            Result = StageResult.Ok,
            Evidence = context.Interface is null
                ? "not pinned; left to the routing table"
                : $"{context.Interface.Name}, index {context.InterfaceIndex}"
                  + (context.UnicastInterfaceOptionUsed ? ", pinned with IP_UNICAST_IF" : ", bind only"),
        });

        // ---- 2. routing decision --------------------------------------------------
        if (route is not null)
        {
            stages.Add(new ProbeStage
            {
                Name = "Route",
                Result = StageResult.Ok,
                Evidence = $"GetBestRoute2: index {route.InterfaceIndex} via {route.NextHopDisplay}, "
                           + $"metric {route.Metric}",
            });
        }
        else if (routeError is not null)
        {
            bool noRoute = routeError.StartsWith("no route", StringComparison.OrdinalIgnoreCase)
                           || routeError.StartsWith("the routing table has no entry", StringComparison.OrdinalIgnoreCase);

            stages.Add(new ProbeStage
            {
                Name = "Route",
                Result = noRoute ? StageResult.Failed : StageResult.Unknown,
                Evidence = noRoute ? "GetBestRoute2: no route to the destination" : routeError,
            });
        }

        // ---- 3. next hop at layer 2 -----------------------------------------------
        if (neighbour is not null && neighbour.WasQueried)
        {
            StageResult result = neighbour.State switch
            {
                null => StageResult.Failed,
                NeighbourState.Unreachable or NeighbourState.Incomplete => StageResult.Failed,
                NeighbourState.Reachable or NeighbourState.Permanent => StageResult.Ok,
                _ => StageResult.Unknown,
            };

            stages.Add(new ProbeStage
            {
                Name = "Next hop",
                Result = result,
                Evidence = $"neighbour cache: {neighbour.Summary()}",
            });
        }

        // ---- 4. socket ------------------------------------------------------------
        bool socketFailed = attempt.Outcome
            is DnsQueryOutcome.ConfigurationError
            or DnsQueryOutcome.SocketFailure
            or DnsQueryOutcome.AccessDenied;

        stages.Add(new ProbeStage
        {
            Name = "Socket",
            Result = socketFailed ? StageResult.Failed : StageResult.Ok,
            Evidence = socketFailed
                ? attempt.ErrorMessage ?? "the socket could not be created or bound"
                : attempt.LocalEndPoint is null
                    ? "created and bound"
                    : $"bound to {attempt.LocalEndPoint}",
        });

        // ---- 5. handing the query to the stack ------------------------------------
        // Named "Send" rather than "Packet TX" on purpose: what is known is that the stack
        // accepted it, not that a frame left the adapter.
        bool sendRejected = attempt.Outcome
            is DnsQueryOutcome.NetworkUnreachable
            or DnsQueryOutcome.HostUnreachable
            or DnsQueryOutcome.PinnedInterfaceUnreachable;

        stages.Add(new ProbeStage
        {
            Name = "Send",
            Result = sendRejected ? StageResult.Failed : socketFailed ? StageResult.Skipped : StageResult.Ok,
            Evidence = sendRejected
                ? "the stack rejected the send: " + DiagnosticReporter.DescribeOutcome(attempt.Outcome)
                : socketFailed
                    ? "not attempted"
                    : $"{attempt.QueryBytes?.Length ?? 0} bytes accepted by the stack "
                      + "(not proof that a frame reached the wire)",
        });

        // ---- 6. response ----------------------------------------------------------
        StageResult receive = attempt.Outcome switch
        {
            DnsQueryOutcome.Success => StageResult.Ok,
            DnsQueryOutcome.Timeout => StageResult.Failed,
            DnsQueryOutcome.ConnectionRefused => StageResult.Failed,
            DnsQueryOutcome.MalformedResponse => StageResult.Failed,
            _ when sendRejected || socketFailed => StageResult.Skipped,
            _ => StageResult.Failed,
        };

        stages.Add(new ProbeStage
        {
            Name = "Receive",
            Result = receive,
            Evidence = receive switch
            {
                StageResult.Ok => $"{attempt.ResponseBytes?.Length ?? 0} bytes from {attempt.RemoteEndPoint}",
                StageResult.Skipped => "not attempted",
                _ => attempt.ErrorMessage ?? DiagnosticReporter.DescribeOutcome(attempt.Outcome),
            },
        });

        // ---- 7. the DNS answer itself ---------------------------------------------
        if (attempt.Response is DnsMessage response)
        {
            bool ok = response.Header.ResponseCode == DnsResponseCode.NoError;
            int answers = response.Answers.Count;

            stages.Add(new ProbeStage
            {
                Name = "DNS answer",
                Result = ok && answers > 0 ? StageResult.Ok : ok ? StageResult.Unknown : StageResult.Failed,
                Evidence = ok
                    ? answers > 0
                        ? $"{response.ResponseCodeDisplay()}, {answers} record(s)"
                        : $"{response.ResponseCodeDisplay()}, no records of that type"
                    : $"server returned {response.ResponseCodeDisplay()}",
            });
        }

        return stages;
    }
}
