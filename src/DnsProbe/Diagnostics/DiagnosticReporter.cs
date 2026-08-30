using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Diagnostics;

/// <summary>Everything that has been resolved before the first packet is sent.</summary>
public sealed class ProbeContext
{
    public required string QueryName { get; init; }

    public required string WireName { get; init; }

    public required DnsRecordType RecordType { get; init; }

    public required DnsTransport Transport { get; init; }

    public required IPEndPoint Server { get; init; }

    public required string ServerSource { get; init; }

    public InterfaceInfo? Interface { get; init; }

    public int? InterfaceIndex { get; init; }

    public IPAddress? SourceAddress { get; init; }

    public required int TimeoutMilliseconds { get; init; }

    public required int Retries { get; init; }

    public required AddressFamily Family { get; init; }

    public bool UnicastInterfaceOptionUsed { get; init; }

    /// <summary>The EDNS(0) options that were requested, or null when EDNS is off.</summary>
    public EdnsOptions? Edns { get; init; }

    /// <summary>"via Ethernet 2 (10.10.10.20)" - used in the closing summary line.</summary>
    public string DescribePath()
    {
        string nic = Interface?.Name ?? "routing table";
        return SourceAddress is null ? $"via {nic}" : $"via {nic} ({SourceAddress})";
    }
}

/// <summary>
/// All console output lives here so that the network and DNS layers stay free of formatting.
/// </summary>
public sealed class DiagnosticReporter
{
    private const string Separator = "----------------------------------------";

    private readonly TextWriter _out;
    private readonly TextWriter _error;
    private ConsoleTheme _theme = new(false);

    public DiagnosticReporter(TextWriter? output = null, TextWriter? error = null)
    {
        _out = output ?? Console.Out;
        _error = error ?? Console.Error;
    }

    /// <summary>
    /// Enables ANSI colour. Off by default so that tests and redirected output stay plain;
    /// the entry point turns it on once the command line has been parsed.
    /// </summary>
    public bool UseColor
    {
        get => _theme.Enabled;
        set => _theme = new ConsoleTheme(value);
    }

    public void WriteLine(string text = "") => _out.WriteLine(text);

    public void WriteError(string message) => _error.WriteLine(_theme.Bad("ERROR: " + message));

    public void WriteWarning(string message) => _out.WriteLine(_theme.Caution("WARNING: " + message));

    public void WriteWarnings(IReadOnlyList<string> warnings)
    {
        foreach (string warning in warnings)
        {
            WriteWarning(warning);
        }
    }

    // ---------------------------------------------------------------- formatting helpers

    private void WriteHeading(string title)
    {
        _out.WriteLine(_theme.Heading(title));
        _out.WriteLine(_theme.Label(Separator));
    }

    /// <summary>Writes "Label   : value" with the label dimmed and the value left as given.</summary>
    private void WriteField(string label, string value, int width)
    {
        _out.WriteLine(_theme.Label(label.PadRight(width) + ": ") + value);
    }

    // ---------------------------------------------------------------- interfaces

    public void WriteInterfaceList(IReadOnlyList<InterfaceInfo> interfaces, bool showAll)
    {
        WriteHeading("Available Network Interfaces");

        int shown = 0;
        int hidden = 0;

        for (int i = 0; i < interfaces.Count; i++)
        {
            InterfaceInfo nic = interfaces[i];

            if (!showAll && (nic.IsLoopback || !nic.IsUp))
            {
                hidden++;
                continue;
            }

            shown++;
            _out.WriteLine(_theme.Label($"[{i + 1}] ") + _theme.Heading(nic.Name));
            WriteIndentedField("Description", nic.Description);
            WriteIndentedField("Kind", _theme.Category(nic.Category, $"{nic.CategoryLabel} ({nic.Type})"));
            WriteIndentedField("Status", _theme.Status(nic.IsUp, nic.Status.ToString()));
            WriteIndentedField(
                "Index",
                $"IPv4 {FormatIndex(nic.Ipv4Index)}, IPv6 {FormatIndex(nic.Ipv6Index)}");
            WriteAddressList("IPv4", nic.Ipv4Addresses);
            WriteAddressList("IPv6", nic.Ipv6Addresses);
            WriteAddressList("Gateway", nic.Gateways);
            WriteAddressList("DNS", nic.DnsServers);
            _out.WriteLine();
        }

        if (shown == 0)
        {
            _out.WriteLine("(no active, non-loopback interfaces found)");
            _out.WriteLine();
        }

        if (hidden > 0)
        {
            _out.WriteLine(_theme.Label($"{hidden} loopback/inactive interface(s) hidden. Use --all to show them."));
        }
    }

    private void WriteIndentedField(string label, string value)
    {
        _out.WriteLine(_theme.Label("    " + label.PadRight(12) + ": ") + value);
    }

    private void WriteAddressList(string label, IReadOnlyList<IPAddress> addresses)
    {
        if (addresses.Count == 0)
        {
            return;
        }

        WriteIndentedField(label, string.Join(", ", addresses));
    }

    private static string FormatIndex(int index) =>
        index == 0 ? "-" : index.ToString(CultureInfo.InvariantCulture);

    // ---------------------------------------------------------------- probe header

    public void WriteProbeHeader(ProbeContext context, bool verbose)
    {
        WriteHeading("DNS Probe");
        WriteField("Query", context.QueryName, 16);

        if (!string.Equals(context.QueryName, context.WireName, StringComparison.Ordinal))
        {
            WriteField("Wire Name", context.WireName, 16);
        }

        WriteField("Record Type", context.RecordType.ToDisplayString(), 16);
        WriteField("Protocol", context.Transport.ToString().ToUpperInvariant(), 16);
        WriteField("Address Family", context.Family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4", 16);

        // The three values below are the ones the user actually controls, so they are highlighted.
        WriteField(
            "Interface",
            context.Interface is null
                ? _theme.Label("(chosen by the routing table)")
                : _theme.Selected(context.Interface.Name),
            16);

        WriteField(
            "Interface Index",
            context.InterfaceIndex is int idx
                ? _theme.Selected(idx.ToString(CultureInfo.InvariantCulture))
                : _theme.Label("-"),
            16);

        WriteField(
            "Source IP",
            context.SourceAddress is null
                ? _theme.Label("(chosen by the routing table)")
                : _theme.Selected(context.SourceAddress.ToString()),
            16);

        WriteField("DNS Server", context.Server.Address.ToString(), 16);
        WriteField("Server Source", context.ServerSource, 16);
        WriteField("Destination Port", context.Server.Port.ToString(CultureInfo.InvariantCulture), 16);
        WriteField("Timeout", $"{context.TimeoutMilliseconds} ms", 16);

        if (verbose)
        {
            WriteField("EDNS", DescribeRequestedEdns(context.Edns), 16);
            WriteField("Retries", context.Retries.ToString(CultureInfo.InvariantCulture), 16);
            WriteField(
                "Interface Pin",
                context.UnicastInterfaceOptionUsed
                    ? _theme.Selected(DescribeUnicastOption(context.Family))
                    : _theme.Label("(disabled)"),
                16);
        }
    }

    private static string DescribeUnicastOption(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? "IPV6_UNICAST_IF" : "IP_UNICAST_IF";

    // ---------------------------------------------------------------- route check

    public void WriteRouteCheck(
        ProbeContext context,
        RouteInfo? route,
        string? routeError,
        int? bestInterfaceIndex,
        IReadOnlyList<InterfaceInfo> interfaces,
        IReadOnlyList<string> warnings)
    {
        _out.WriteLine();
        WriteHeading("Route Check");
        WriteField("Destination", context.Server.Address.ToString(), 12);
        WriteField(
            "Source",
            context.SourceAddress is null ? _theme.Label("(not pinned)") : _theme.Selected(context.SourceAddress.ToString()),
            12);
        WriteField(
            "Interface",
            context.Interface is null ? _theme.Label("(not pinned)") : _theme.Selected(context.Interface.Name),
            12);

        if (route is null)
        {
            string message = routeError ?? "unknown error";

            // "No route" is a diagnostic answer, not a malfunction, so it is not shown in red.
            bool isFinding = message.StartsWith("no route", StringComparison.OrdinalIgnoreCase)
                             || message.StartsWith("the routing table has no entry", StringComparison.OrdinalIgnoreCase);

            WriteField("Routing", isFinding ? _theme.Caution(message) : _theme.Bad("unavailable - " + message), 12);
            return;
        }

        string routeInterfaceName = ResolveInterfaceName(interfaces, route.InterfaceIndex, context.Family);

        WriteField("Gateway", route.NextHopDisplay, 12);

        // Green when the routing table agrees with the interface the user asked for.
        bool agrees = context.InterfaceIndex is null || context.InterfaceIndex == route.InterfaceIndex;
        string egress = $"{routeInterfaceName} (index {route.InterfaceIndex}, metric {route.Metric})";
        WriteField("Route Egress", agrees ? _theme.Good(egress) : _theme.Caution(egress), 12);

        if (route.BestSourceAddress is not null)
        {
            bool sameSource = context.SourceAddress is null || route.BestSourceAddress.Equals(context.SourceAddress);
            string sourceText = route.BestSourceAddress.ToString();
            WriteField(
                "Route Source",
                (sameSource ? _theme.Good(sourceText) : _theme.Caution(sourceText))
                    + _theme.Label(" (what Windows would pick without an explicit bind)"),
                12);
        }

        if (bestInterfaceIndex is int best && best != route.InterfaceIndex)
        {
            _out.WriteLine(_theme.Caution($"GetBestInterfaceEx disagrees and reports index {best}."));
        }

        foreach (string warning in warnings)
        {
            WriteWarning(warning);
        }
    }

    private static string ResolveInterfaceName(IReadOnlyList<InterfaceInfo> interfaces, int index, AddressFamily family)
    {
        foreach (InterfaceInfo nic in interfaces)
        {
            if (nic.IndexFor(family) == index || nic.Ipv4Index == index || nic.Ipv6Index == index)
            {
                return nic.Name;
            }
        }

        return "(unknown interface)";
    }

    // ---------------------------------------------------------------- results

    public void WriteAttempt(DnsQueryAttempt attempt, ProbeContext context, bool verbose, bool debug)
    {
        _out.WriteLine();

        if (attempt.LocalEndPoint is not null && verbose)
        {
            WriteField("Local endpoint", _theme.Selected(Describe(attempt.LocalEndPoint)), 16);
            WriteField("Remote endpoint", Describe(attempt.RemoteEndPoint), 16);
        }

        if (!attempt.IsSuccess)
        {
            WriteError(attempt.ErrorMessage ?? $"The query failed ({attempt.Outcome}).");
            WriteNotes(attempt, verbose);
            WriteHexDumps(attempt, debug);
            return;
        }

        DnsMessage response = attempt.Response!;

        _out.WriteLine(_theme.Good("Response received."));
        WriteField("Round Trip Time", _theme.RoundTrip(attempt.RoundTripTime.TotalMilliseconds), 16);
        WriteField("Transaction ID", $"0x{attempt.TransactionId:X4}", 16);
        WriteField("Response Code", _theme.Outcome(response.Header.ResponseCode.ToDisplayString()), 16);
        WriteField("Transport", attempt.Transport.ToString().ToUpperInvariant(), 16);

        if (verbose)
        {
            WriteField("Flags", response.Header.FlagsString(), 16);
            WriteField("  Authoritative", YesNo(response.Header.AuthoritativeAnswer), 16);
            WriteField(
                "  Truncated",
                response.Header.Truncated ? _theme.Caution("yes") : "no",
                16);
            WriteField("  Recursion Des.", YesNo(response.Header.RecursionDesired), 16);
            WriteField("  Recursion Av.", YesNo(response.Header.RecursionAvailable), 16);
            WriteField(
                "Counts",
                $"{response.Header.QuestionCount} question, {response.Header.AnswerCount} answer, "
                + $"{response.Header.AuthorityCount} authority, {response.Header.AdditionalCount} additional",
                16);
        }
        else
        {
            WriteField("Answer Count", response.Answers.Count.ToString(CultureInfo.InvariantCulture), 16);
        }

        WriteEdnsResponse(response, verbose);

        if (response.Header.ResponseCode != DnsResponseCode.NoError)
        {
            _out.WriteLine();
            _out.WriteLine(_theme.Outcome(response.Header.ResponseCode.ToDisplayString())
                           + " - the DNS server rejected or could not answer the query.");
            _out.WriteLine(response.Header.ResponseCode.Explain());
        }

        WriteSection("Answer", response.Answers);

        if (verbose)
        {
            WriteSection("Authority", response.Authorities);
            WriteSection("Additional", response.Additionals);
        }

        if (response.Answers.Count == 0 && response.Header.ResponseCode == DnsResponseCode.NoError)
        {
            _out.WriteLine();
            _out.WriteLine(_theme.Caution(
                $"The server answered without error but returned no {context.RecordType.ToDisplayString()} "
                + $"record for {context.WireName}."));
        }

        if (response.Header.Truncated)
        {
            _out.WriteLine();
            WriteWarning("The response is truncated (TC=1). Use --tcp-fallback or --tcp to receive the full answer.");
        }

        foreach (string warning in response.Warnings)
        {
            WriteWarning(warning);
        }

        WriteNotes(attempt, verbose);
        WriteHexDumps(attempt, debug);
    }

    private string DescribeRequestedEdns(EdnsOptions? edns)
    {
        if (edns is null || !edns.Enabled)
        {
            return _theme.Label("(disabled)");
        }

        var parts = new List<string> { $"UDP payload {edns.UdpPayloadSize}" };

        if (edns.DnssecOk)
        {
            parts.Add("DO");
        }

        if (edns.RequestNsid)
        {
            parts.Add("NSID");
        }

        return _theme.Selected("version 0, " + string.Join(", ", parts));
    }

    /// <summary>
    /// Reports what the server said in its OPT record. The extended error is always shown, even
    /// without --verbose, because it usually explains a SERVFAIL that would otherwise be a mystery.
    /// </summary>
    private void WriteEdnsResponse(DnsMessage response, bool verbose)
    {
        EdnsResponse? edns = response.Edns;

        if (edns is null)
        {
            if (verbose)
            {
                WriteField("EDNS Response", _theme.Caution("none - the server answered without an OPT record"), 16);
            }

            return;
        }

        if (verbose)
        {
            var parts = new List<string> { $"version {edns.Version}", $"UDP payload {edns.UdpPayloadSize}" };

            if (edns.DnssecOk)
            {
                parts.Add("DO");
            }

            WriteField("EDNS Response", string.Join(", ", parts), 16);

            int fullCode = edns.FullResponseCode(response.Header.ResponseCode);
            if (fullCode > 15)
            {
                WriteField("Extended RCODE", _theme.Outcome(edns.DescribeFullResponseCode(response.Header.ResponseCode)), 16);
            }

            foreach (EdnsUnknownOption option in edns.OtherOptions)
            {
                WriteField("EDNS Option", _theme.Label(option.Describe()), 16);
            }
        }

        if (edns.Nsid is not null)
        {
            WriteField("Server NSID", _theme.Selected(edns.Nsid), 16);
        }

        if (edns.DescribeExtendedError() is string extendedError)
        {
            WriteField("Extended Error", _theme.Caution(extendedError), 16);
        }
    }

    private void WriteSection(string title, IReadOnlyList<DnsRecord> records)
    {
        // OPT is a pseudo-record, not data. It is summarised on the EDNS lines above, so showing
        // it again here would only be noise - dig hides it from the additional section too.
        var visible = new List<DnsRecord>(records.Count);
        foreach (DnsRecord candidate in records)
        {
            if (candidate.Type != DnsRecordType.OPT)
            {
                visible.Add(candidate);
            }
        }

        if (visible.Count == 0)
        {
            return;
        }

        _out.WriteLine();
        _out.WriteLine(_theme.Heading(title + ":"));

        foreach (DnsRecord record in visible)
        {
            _out.WriteLine($"  {record.Name} " + _theme.Label("->") + " " + _theme.Good(record.Value));
            _out.WriteLine(_theme.Label("    Type        : ") + record.Type.ToDisplayString());
            _out.WriteLine(_theme.Label("    TTL         : ") + $"{record.TimeToLive} s");
        }
    }

    private void WriteNotes(DnsQueryAttempt attempt, bool verbose)
    {
        if (!verbose || attempt.Notes.Count == 0)
        {
            return;
        }

        _out.WriteLine();
        _out.WriteLine(_theme.Caution("Notes:"));
        foreach (string note in attempt.Notes)
        {
            _out.WriteLine(_theme.Caution("  - " + note));
        }
    }

    private void WriteHexDumps(DnsQueryAttempt attempt, bool debug)
    {
        if (!debug)
        {
            return;
        }

        _out.WriteLine();
        WriteHeading("Packet Trace");
        WriteField("Local endpoint", Describe(attempt.LocalEndPoint), 16);
        WriteField("Remote endpoint", Describe(attempt.RemoteEndPoint), 16);

        if (attempt.QueryBytes is not null)
        {
            _out.WriteLine(_theme.Label($"TX ({attempt.QueryBytes.Length} bytes):"));
            _out.WriteLine(HexDump.Format(attempt.QueryBytes));
        }

        if (attempt.ResponseBytes is not null)
        {
            _out.WriteLine(_theme.Label($"RX ({attempt.ResponseBytes.Length} bytes):"));
            _out.WriteLine(HexDump.Format(attempt.ResponseBytes));
        }
    }

    private static string Describe(IPEndPoint? endPoint) => endPoint is null ? "(none)" : endPoint.ToString();

    private static string YesNo(bool value) => value ? "yes" : "no";

    public static string FormatMilliseconds(double value) =>
        value.ToString(value < 10 ? "0.00" : "0.0", CultureInfo.InvariantCulture) + " ms";

    // ---------------------------------------------------------------- repeated queries

    public void WriteQueryLine(int index, DnsQueryAttempt attempt)
    {
        string prefix = _theme.Label($"Query {index}: ");

        if (attempt.IsSuccess)
        {
            string rcode = attempt.Response!.Header.ResponseCode == DnsResponseCode.NoError
                ? string.Empty
                : " " + _theme.Outcome(attempt.Response.Header.ResponseCode.ToDisplayString());

            _out.WriteLine(prefix + _theme.RoundTrip(attempt.RoundTripTime.TotalMilliseconds) + rcode);
        }
        else
        {
            _out.WriteLine(prefix + _theme.Outcome(DescribeOutcome(attempt.Outcome)));
        }
    }

    public void WriteStatistics(QueryStatistics statistics)
    {
        _out.WriteLine();
        WriteHeading("Statistics");
        WriteField("Sent", statistics.Sent.ToString(CultureInfo.InvariantCulture), 9);
        WriteField("Received", statistics.Received.ToString(CultureInfo.InvariantCulture), 9);
        WriteField(
            "Lost",
            $"{statistics.Lost} (" + _theme.Loss(statistics.LossPercentage) + ")",
            9);

        if (statistics.Minimum is double min)
        {
            WriteField("Min", _theme.RoundTrip(min), 9);
            WriteField("Max", _theme.RoundTrip(statistics.Maximum!.Value), 9);
            WriteField("Average", _theme.RoundTrip(statistics.Average!.Value), 9);

            if (statistics.Jitter is double jitter)
            {
                WriteField("Jitter", FormatMilliseconds(jitter), 9);
            }
        }
    }

    public static string DescribeOutcome(DnsQueryOutcome outcome) => outcome switch
    {
        DnsQueryOutcome.Success => "SUCCESS",
        DnsQueryOutcome.Timeout => "TIMEOUT",
        DnsQueryOutcome.NetworkUnreachable => "NET-UNREACH",
        DnsQueryOutcome.HostUnreachable => "HOST-UNREACH",
        // Deliberately not "REFUSED": that name belongs to the DNS RCODE, which means the
        // server answered and declined. This one means nothing is listening on the port at all.
        DnsQueryOutcome.ConnectionRefused => "PORT-UNREACH",
        DnsQueryOutcome.PinnedInterfaceUnreachable => "IF-UNREACH",
        DnsQueryOutcome.AccessDenied => "DENIED",
        DnsQueryOutcome.SocketFailure => "SOCKET-ERR",
        DnsQueryOutcome.MalformedResponse => "MALFORMED",
        DnsQueryOutcome.ConfigurationError => "CONFIG-ERR",
        _ => outcome.ToString().ToUpperInvariant(),
    };

    // ---------------------------------------------------------------- compare

    public void WriteComparisonTable(IReadOnlyList<ComparisonRow> rows)
    {
        _out.WriteLine();
        _out.WriteLine(_theme.Heading(
            $"{"Interface",-24} {"Source IP",-24} {"Result",-14} {"RTT",-10}"));
        _out.WriteLine(_theme.Label(new string('-', 76)));

        foreach (ComparisonRow row in rows)
        {
            // Padding is applied before the colour codes so the columns stay aligned.
            string rtt = row.RoundTripMilliseconds is double value
                ? _theme.RoundTrip(value)
                : _theme.Label("-");

            _out.WriteLine(
                Truncate(row.InterfaceName, 24).PadRight(24)
                + " " + _theme.Selected(Truncate(row.SourceAddress, 24).PadRight(24))
                + " " + _theme.Outcome(row.Result, 14)
                + " " + rtt);
        }

        _out.WriteLine();

        foreach (ComparisonRow row in rows)
        {
            if (row.Detail is not null)
            {
                _out.WriteLine(_theme.Label($"{row.InterfaceName}: ") + row.Detail);
            }
        }
    }

    private static string Truncate(string value, int length) =>
        value.Length <= length ? value : value[..(length - 1)] + "~";

    public void WriteInterfaceSummaryLine(InterfaceInfo nic, AddressFamily family)
    {
        _out.WriteLine($"  {nic.Name} " + _theme.Label($"(index {nic.IndexFor(family)}, {nic.CategoryLabel}, {nic.Status})"));
    }

    public void WriteStatusHint(OperationalStatus status)
    {
        if (status != OperationalStatus.Up)
        {
            WriteWarning($"The selected interface is {status}.");
        }
    }

    /// <summary>
    /// Prints the heuristic observations. Kept visually distinct from warnings: these are things
    /// worth looking at, not things that went wrong.
    /// </summary>
    public void WriteObservations(IReadOnlyList<string> observations)
    {
        if (observations.Count == 0)
        {
            return;
        }

        _out.WriteLine();
        _out.WriteLine(_theme.Heading("Observations"));
        _out.WriteLine(_theme.Label(Separator));

        foreach (string observation in observations)
        {
            _out.WriteLine(_theme.Caution("  - " + observation));
        }
    }

    // ---------------------------------------------------------------- closing summary

    /// <summary>
    /// One line at the very bottom that answers "so what happened?" without re-reading the output.
    /// </summary>
    private void WriteSummary(string verdict, string detail)
    {
        _out.WriteLine();
        _out.WriteLine(_theme.Label("RESULT: ") + verdict + (detail.Length > 0 ? " - " + detail : string.Empty));
    }

    public void WriteAttemptSummary(DnsQueryAttempt attempt, ProbeContext context)
    {
        if (!attempt.IsSuccess)
        {
            WriteSummary(
                _theme.Outcome(DescribeOutcome(attempt.Outcome)),
                $"no usable answer from {context.Server.Address} {context.DescribePath()}");
            return;
        }

        DnsMessage response = attempt.Response!;
        string rtt = FormatMilliseconds(attempt.RoundTripTime.TotalMilliseconds);

        if (response.Header.ResponseCode != DnsResponseCode.NoError)
        {
            WriteSummary(
                _theme.Outcome(response.Header.ResponseCode.ToDisplayString()),
                $"{context.Server.Address} answered in {rtt} {context.DescribePath()}");
            return;
        }

        if (response.Answers.Count == 0)
        {
            WriteSummary(
                _theme.Outcome("NODATA"),
                $"no {context.RecordType.ToDisplayString()} record for {context.QueryName} ({rtt})");
            return;
        }

        string first = response.Answers[0].Value;
        string more = response.Answers.Count > 1 ? $" (+{response.Answers.Count - 1} more)" : string.Empty;

        WriteSummary(_theme.Outcome("OK"), $"{first}{more} in {rtt} {context.DescribePath()}");
    }

    public void WriteStatisticsSummary(QueryStatistics statistics, ProbeContext context)
    {
        string received = $"{statistics.Received}/{statistics.Sent} received";

        if (statistics.Received == 0)
        {
            WriteSummary(_theme.Bad("NO RESPONSE"), $"{received} from {context.Server.Address} {context.DescribePath()}");
            return;
        }

        string average = statistics.Average is double avg ? $", avg {FormatMilliseconds(avg)}" : string.Empty;
        string verdict = statistics.Lost == 0 ? _theme.Good("OK") : _theme.Caution("PARTIAL LOSS");

        WriteSummary(verdict, $"{received}{average} {context.DescribePath()}");
    }

    public void WriteComparisonSummary(IReadOnlyList<ComparisonRow> rows, IPEndPoint server)
    {
        var succeeded = new List<string>();

        foreach (ComparisonRow row in rows)
        {
            if (string.Equals(row.Result, "SUCCESS", StringComparison.Ordinal))
            {
                succeeded.Add(row.InterfaceName);
            }
        }

        if (succeeded.Count == 0)
        {
            WriteSummary(
                _theme.Bad("UNREACHABLE"),
                $"none of the {rows.Count} interface(s) could reach {server.Address}");
            return;
        }

        string verdict = succeeded.Count == rows.Count ? _theme.Good("OK") : _theme.Caution("PARTIAL");

        WriteSummary(
            verdict,
            $"{succeeded.Count} of {rows.Count} interface(s) reached {server.Address}: {string.Join(", ", succeeded)}");
    }
}

/// <summary>One line of the --compare table.</summary>
public sealed class ComparisonRow
{
    public required string InterfaceName { get; init; }

    public required string SourceAddress { get; init; }

    public required string Result { get; init; }

    public double? RoundTripMilliseconds { get; init; }

    public string? Detail { get; init; }
}
