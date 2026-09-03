using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsProbe.Network;

namespace DnsProbe.Dns;

/// <summary>What happened at one step of the delegation chain.</summary>
public enum TraceStepOutcome
{
    /// <summary>The server pointed at the next zone down. This is the normal case.</summary>
    Referral,

    /// <summary>The server answered the question.</summary>
    Answer,

    /// <summary>The server is authoritative and the name exists, but not for this record type.</summary>
    NoData,

    /// <summary>The server is authoritative and the name does not exist.</summary>
    NameError,

    /// <summary>Nothing usable came back.</summary>
    Failed,
}

/// <summary>One query in the chain.</summary>
public sealed class TraceStep
{
    /// <summary>The zone this server is authoritative for. "." for the root.</summary>
    public required string Zone { get; init; }

    public required string ServerName { get; init; }

    public required IPAddress ServerAddress { get; init; }

    public required TraceStepOutcome Outcome { get; init; }

    public double? RoundTripMilliseconds { get; init; }

    /// <summary>The zone we were referred to, when this step was a referral.</summary>
    public string? NextZone { get; init; }

    /// <summary>How many name servers the referral offered.</summary>
    public int NextServerCount { get; init; }

    public DnsMessage? Response { get; init; }

    public string? Error { get; init; }

    /// <summary>Things worth mentioning that are not failures, e.g. a missing glue record.</summary>
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();
}

/// <summary>The whole chain.</summary>
public sealed class TraceResult
{
    public required IReadOnlyList<TraceStep> Steps { get; init; }

    /// <summary>The authoritative answer, when the chain reached one.</summary>
    public DnsMessage? Answer { get; init; }

    /// <summary>Why the walk stopped short, when it did.</summary>
    public string? StoppedBecause { get; init; }

    public required TimeSpan Elapsed { get; init; }

    public bool Succeeded => Answer is not null;
}

/// <summary>
/// Walks the delegation chain from the root servers down to the authoritative server, the way a
/// real resolver does, asking each level with recursion disabled.
///
/// This answers a question no single query can: when a name fails to resolve, which link in the
/// chain is broken - the root, the TLD, the registrar's delegation, or the zone's own servers.
/// It also makes interception obvious, because a resolver that answers on behalf of a root server
/// is not something that happens on a healthy path.
///
/// The socket binding is honoured throughout, so a trace can be run from one specific interface.
/// </summary>
public sealed class DnsTracer
{
    /// <summary>
    /// Root hints. These addresses are deliberately hard-coded: asking a resolver where the root
    /// servers are would defeat the purpose of starting from the root. They change very rarely;
    /// the current list is published at https://www.iana.org/domains/root/servers
    /// </summary>
    private static readonly (string Name, string V4, string V6)[] RootServers =
    {
        ("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"),
        ("b.root-servers.net", "170.247.170.2", "2801:1b8:10::b"),
        ("c.root-servers.net", "192.33.4.12", "2001:500:2::c"),
        ("d.root-servers.net", "199.7.91.13", "2001:500:2d::d"),
        ("e.root-servers.net", "192.203.230.10", "2001:500:a8::e"),
        ("f.root-servers.net", "192.5.5.241", "2001:500:2f::f"),
        ("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"),
        ("h.root-servers.net", "198.97.190.53", "2001:500:1::53"),
        ("i.root-servers.net", "192.36.148.17", "2001:7fe::53"),
        ("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"),
        ("k.root-servers.net", "193.0.14.129", "2001:7fd::1"),
        ("l.root-servers.net", "199.7.83.42", "2001:500:9f::42"),
        ("m.root-servers.net", "202.12.27.33", "2001:dc3::35"),
    };

    /// <summary>A chain deeper than this is malformed, not merely long.</summary>
    private const int MaxDepth = 20;

    /// <summary>
    /// Default number of servers to try at one level. Without a cap a blocked path would spend
    /// thirteen timeouts on the root alone before reporting anything.
    /// </summary>
    public const int DefaultServersPerLevel = 3;

    private readonly DnsClient _client;

    public DnsTracer(DnsClient client)
    {
        _client = client;
    }

    public async Task<TraceResult> TraceAsync(
        string wireName,
        DnsRecordType recordType,
        DnsRecordClass recordClass,
        SocketBinding binding,
        AddressFamily family,
        DnsTransport transport,
        int timeoutMilliseconds,
        EdnsOptions? edns,
        int serversPerLevel,
        CancellationToken cancellationToken)
    {
        if (serversPerLevel < 1)
        {
            serversPerLevel = 1;
        }

        var steps = new List<TraceStep>();
        var visitedZones = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stopwatch = Stopwatch.StartNew();

        List<(string Name, IPAddress Address)> servers = RootServerList(family);
        string zone = ".";
        string? stopped = null;
        DnsMessage? answer = null;

        for (int depth = 0; depth < MaxDepth; depth++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (servers.Count == 0)
            {
                stopped = $"No usable name server address was available for zone \"{zone}\".";
                break;
            }

            // One server per level is normally enough: every server for a zone holds the same data,
            // so querying all thirteen roots would produce thirteen identical referrals and bury
            // the useful line. But a server that does not answer must not end the walk, because a
            // real resolver would simply try the next one - so we do too, and say that we did.
            var attempted = new List<string>();
            string? serverName = null;
            IPAddress? serverAddress = null;
            DnsQueryAttempt? attempt = null;

            foreach ((string candidateName, IPAddress candidateAddress) in servers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var request = new DnsQueryRequest
                {
                    Name = wireName,
                    RecordType = recordType,
                    RecordClass = recordClass,
                    Server = new IPEndPoint(candidateAddress, 53),
                    Binding = binding,
                    TimeoutMilliseconds = timeoutMilliseconds,

                    // A trace asks each level itself, so recursion must be off. A server that
                    // answers a non-recursive query it is not authoritative for is not playing by
                    // the rules.
                    RecursionDesired = false,
                    Transport = transport,
                    Edns = edns,
                };

                DnsQueryResult candidateResult = await _client
                    .QueryAsync(request, retries: 0, tcpFallback: true, cancellationToken)
                    .ConfigureAwait(false);

                serverName = candidateName;
                serverAddress = candidateAddress;
                attempt = candidateResult.Final;

                if (attempt.IsSuccess && attempt.Response is not null)
                {
                    break;
                }

                attempted.Add($"{candidateName} ({DescribeFailure(attempt)})");

                if (attempted.Count >= serversPerLevel)
                {
                    break;
                }
            }

            var levelNotes = new List<string>();

            if (attempted.Count > 0 && attempt is { IsSuccess: true })
            {
                // Prefixed so the reporter can render a dead server differently from an ordinary
                // note: a name server that will not answer is a finding, not a footnote.
                levelNotes.Add(SkipNotePrefix + (attempted.Count == 1
                    ? $"no answer from {attempted[0]}"
                    : $"no answer from {attempted.Count} server(s): {string.Join("; ", attempted)}"));
            }

            if (attempt is null || !attempt.IsSuccess || attempt.Response is null)
            {
                steps.Add(new TraceStep
                {
                    Zone = zone,
                    ServerName = serverName ?? "(none)",
                    ServerAddress = serverAddress ?? IPAddress.None,
                    Outcome = TraceStepOutcome.Failed,
                    Error = attempt?.ErrorMessage,
                    Notes = attempted,
                });

                stopped = attempted.Count > 1
                    ? $"The chain stops at zone \"{zone}\": none of the {attempted.Count} name "
                      + "server(s) tried would answer."
                    : $"The chain stops at zone \"{zone}\": {serverName} did not answer.";
                break;
            }

            DnsMessage response = attempt.Response;
            double rtt = attempt.RoundTripTime.TotalMilliseconds;

            // ---- an authoritative answer ends the walk ---------------------------------
            if (response.Header.ResponseCode == DnsResponseCode.NXDomain)
            {
                steps.Add(Step(zone, serverName!, serverAddress!, TraceStepOutcome.NameError, rtt, response, levelNotes));
                stopped = $"{serverName} is authoritative for \"{zone}\" and says the name does not exist.";
                break;
            }

            if (response.Answers.Count > 0)
            {
                steps.Add(Step(zone, serverName!, serverAddress!, TraceStepOutcome.Answer, rtt, response, levelNotes));
                answer = response;
                break;
            }

            // ---- a referral: name servers in the authority section ---------------------
            (string? nextZone, List<string> nsNames) = ReadReferral(response);

            if (nextZone is null)
            {
                // Authoritative, no answer, no referral: the name exists but has no such record.
                steps.Add(Step(zone, serverName!, serverAddress!, TraceStepOutcome.NoData, rtt, response, levelNotes));
                stopped = $"{serverName} is authoritative for \"{zone}\" and holds no "
                          + $"{recordType.ToDisplayString()} record for this name.";
                break;
            }

            if (!visitedZones.Add(nextZone))
            {
                steps.Add(Step(zone, serverName!, serverAddress!, TraceStepOutcome.Failed, rtt, response, levelNotes));
                stopped = $"The delegation loops: \"{nextZone}\" was already visited.";
                break;
            }

            var notes = new List<string>(levelNotes);
            List<(string Name, IPAddress Address)> next = ReadGlue(response, nsNames, family, notes);

            steps.Add(new TraceStep
            {
                Zone = zone,
                ServerName = serverName!,
                ServerAddress = serverAddress!,
                Outcome = TraceStepOutcome.Referral,
                RoundTripMilliseconds = rtt,
                NextZone = nextZone,
                NextServerCount = nsNames.Count,
                Response = response,
                Notes = notes,
            });

            if (next.Count == 0)
            {
                stopped = $"The referral to \"{nextZone}\" carried no address records (no glue), so the "
                          + "chain cannot be followed without a working resolver to look the name "
                          + "servers up first.";
                break;
            }

            servers = next;
            zone = nextZone;
        }

        stopwatch.Stop();

        if (answer is null && stopped is null)
        {
            stopped = $"The delegation chain was still going after {MaxDepth} steps.";
        }

        return new TraceResult
        {
            Steps = steps,
            Answer = answer,
            StoppedBecause = stopped,
            Elapsed = stopwatch.Elapsed,
        };
    }

    private static TraceStep Step(
        string zone,
        string serverName,
        IPAddress serverAddress,
        TraceStepOutcome outcome,
        double rtt,
        DnsMessage response,
        IReadOnlyList<string>? notes = null) => new()
        {
            Zone = zone,
            ServerName = serverName,
            ServerAddress = serverAddress,
            Outcome = outcome,
            RoundTripMilliseconds = rtt,
            Response = response,
            Notes = notes ?? Array.Empty<string>(),
        };

    /// <summary>
    /// Marks a note that describes a name server which did not answer, so the reporter can colour
    /// it as a failure rather than as an aside.
    /// </summary>
    public const string SkipNotePrefix = "!";

    /// <summary>A few words on why a server was passed over.</summary>
    private static string DescribeFailure(DnsQueryAttempt attempt) =>
        attempt.Outcome switch
        {
            DnsQueryOutcome.Timeout => "no reply",
            DnsQueryOutcome.NetworkUnreachable => "no route",
            DnsQueryOutcome.HostUnreachable => "host unreachable",
            DnsQueryOutcome.PinnedInterfaceUnreachable => "no route from the pinned interface",
            DnsQueryOutcome.ConnectionRefused => "nothing listening on port 53",
            DnsQueryOutcome.MalformedResponse => "unreadable reply",
            _ => attempt.Outcome.ToString().ToLowerInvariant(),
        };

    private static List<(string Name, IPAddress Address)> RootServerList(AddressFamily family)
    {
        var list = new List<(string, IPAddress)>();

        foreach ((string name, string v4, string v6) in RootServers)
        {
            string text = family == AddressFamily.InterNetworkV6 ? v6 : v4;

            if (IPAddress.TryParse(text, out IPAddress? address))
            {
                list.Add((name, address));
            }
        }

        return list;
    }

    /// <summary>Extracts the delegated zone and its name server names from the authority section.</summary>
    private static (string? Zone, List<string> Names) ReadReferral(DnsMessage response)
    {
        string? zone = null;
        var names = new List<string>();

        foreach (DnsRecord record in response.Authorities)
        {
            if (record.Type != DnsRecordType.NS)
            {
                continue;
            }

            zone ??= record.Name;
            names.Add(record.Value);
        }

        return (zone, names);
    }

    /// <summary>
    /// Pairs the referred name servers with the glue addresses in the additional section.
    /// A referral without glue cannot be followed without a resolver, which is exactly the thing
    /// a trace is trying to avoid depending on, so that case is reported rather than worked around.
    /// </summary>
    private static List<(string Name, IPAddress Address)> ReadGlue(
        DnsMessage response,
        List<string> nsNames,
        AddressFamily family,
        List<string> notes)
    {
        DnsRecordType wanted = family == AddressFamily.InterNetworkV6 ? DnsRecordType.AAAA : DnsRecordType.A;
        var glue = new List<(string, IPAddress)>();

        foreach (string nsName in nsNames)
        {
            foreach (DnsRecord record in response.Additionals)
            {
                if (record.Type != wanted)
                {
                    continue;
                }

                if (!string.Equals(record.Name.TrimEnd('.'), nsName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (record is AddressRecord address)
                {
                    glue.Add((nsName, address.Address));
                    break;
                }
            }
        }

        if (glue.Count == 0 && nsNames.Count > 0)
        {
            notes.Add($"the referral listed {nsNames.Count} name server(s) but included no "
                      + $"{wanted.ToDisplayString()} glue record");
        }
        else if (glue.Count < nsNames.Count)
        {
            notes.Add($"glue was present for {glue.Count} of {nsNames.Count} name servers");
        }

        return glue;
    }
}
