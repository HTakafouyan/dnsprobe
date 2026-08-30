using System.Net;
using System.Net.Sockets;
using DnsProbe.Cli;
using DnsProbe.Diagnostics;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe;

/// <summary>Process exit codes.</summary>
public static class ExitCodes
{
    public const int Success = 0;
    public const int DnsError = 1;
    public const int NoResponse = 2;
    public const int UsageError = 3;
}

/// <summary>
/// Wires the CLI options to the network, DNS and diagnostics layers.
/// </summary>
public sealed class ProbeRunner
{
    private readonly INetworkInterfaceProvider _provider;
    private readonly DiagnosticReporter _reporter;
    private readonly DnsClient _client;
    private readonly RouteInspector _routeInspector;
    private readonly InterfaceSelector _selector;

    public ProbeRunner(
        INetworkInterfaceProvider provider,
        DiagnosticReporter reporter,
        DnsClient client,
        RouteInspector routeInspector)
    {
        _provider = provider;
        _reporter = reporter;
        _client = client;
        _routeInspector = routeInspector;
        _selector = new InterfaceSelector(provider);
    }

    public async Task<int> RunAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        IReadOnlyList<InterfaceInfo> interfaces = _provider.GetInterfaces();

        if (options.Command == ProbeCommand.ListInterfaces)
        {
            if (options.Json)
            {
                JsonOutput.WriteInterfaces(interfaces, options.ShowAllInterfaces);
            }
            else
            {
                _reporter.WriteInterfaceList(interfaces, options.ShowAllInterfaces);
            }

            return ExitCodes.Success;
        }

        if (options.QueryName is null)
        {
            return Fail(options, "No query name was given.", ExitCodes.UsageError);
        }

        // ---- interface / source selection -------------------------------------------
        InterfaceSelectionResult selection;

        if (options.Compare)
        {
            AddressFamily compareFamily =
                options.ForcedFamily ?? options.ServerAddress?.AddressFamily ?? AddressFamily.InterNetwork;
            selection = InterfaceSelectionResult.Ok(null, null, compareFamily, null);
        }
        else
        {
            selection = _selector.Select(new InterfaceSelectionRequest
            {
                InterfaceName = options.InterfaceName,
                InterfaceIndex = options.InterfaceIndex,
                SourceAddress = options.SourceIp,
                ForcedFamily = options.ForcedFamily,
                ServerAddress = options.ServerAddress,
                AllowDownInterface = options.AllowDownInterface,
            });

            if (!selection.Success)
            {
                return Fail(options, selection.Error!, ExitCodes.UsageError);
            }
        }

        AddressFamily family = selection.Family;

        // ---- DNS server resolution ---------------------------------------------------
        if (!TryResolveServer(options, selection, interfaces, family, out IPEndPoint? server, out string serverSource, out string? serverError))
        {
            return Fail(options, serverError!, ExitCodes.UsageError);
        }

        string wireName;
        try
        {
            wireName = options.ResolveWireName();
        }
        catch (DnsProtocolException ex)
        {
            return Fail(options, ex.Message, ExitCodes.UsageError);
        }

        var context = new ProbeContext
        {
            QueryName = options.QueryName,
            WireName = wireName,
            RecordType = options.RecordType,
            Transport = options.Transport,
            Server = server!,
            ServerSource = serverSource,
            Interface = selection.Interface,
            InterfaceIndex = selection.InterfaceIndex,
            SourceAddress = selection.SourceAddress,
            TimeoutMilliseconds = options.TimeoutMilliseconds,
            Retries = options.Retries,
            Family = family,
            UnicastInterfaceOptionUsed = !options.NoUnicastInterface && selection.InterfaceIndex is not null,
            Edns = options.BuildEdnsOptions(),
        };

        if (!options.Json)
        {
            _reporter.WriteProbeHeader(context, options.Verbose);
            _reporter.WriteWarnings(selection.Warnings);
        }

        // ---- route check -------------------------------------------------------------
        if (options.RouteCheck && !options.Json)
        {
            RunRouteCheck(context, interfaces);
        }

        // ---- compare mode ------------------------------------------------------------
        if (options.Compare)
        {
            return await RunCompareAsync(options, interfaces, context, cancellationToken).ConfigureAwait(false);
        }

        // ---- normal query(s) ---------------------------------------------------------
        var binding = new SocketBinding(
            family,
            options.Transport == DnsTransport.Tcp ? ProtocolType.Tcp : ProtocolType.Udp,
            selection.SourceAddress,
            selection.InterfaceIndex,
            !options.NoUnicastInterface);

        var request = new DnsQueryRequest
        {
            Name = wireName,
            RecordType = options.RecordType,
            Server = server!,
            Binding = binding,
            TimeoutMilliseconds = options.TimeoutMilliseconds,
            RecursionDesired = !options.NoRecursion,
            Transport = options.Transport,
            Edns = context.Edns,
        };

        return options.Count > 1
            ? await RunRepeatedAsync(options, request, context, cancellationToken).ConfigureAwait(false)
            : await RunSingleAsync(options, request, context, cancellationToken).ConfigureAwait(false);
    }

    private async Task<int> RunSingleAsync(
        ProbeOptions options,
        DnsQueryRequest request,
        ProbeContext context,
        CancellationToken cancellationToken)
    {
        DnsQueryResult result = await _client
            .QueryAsync(request, options.Retries, options.TcpFallback, cancellationToken)
            .ConfigureAwait(false);

        for (int i = 0; i < result.Attempts.Count - 1 && !options.Json; i++)
        {
            DnsQueryAttempt failed = result.Attempts[i];
            if (!failed.IsSuccess)
            {
                _reporter.WriteLine();
                _reporter.WriteWarning($"Attempt {i + 1} failed: {failed.ErrorMessage ?? DiagnosticReporter.DescribeOutcome(failed.Outcome)}");
            }
        }

        if (result.UsedTcpFallback)
        {
            _reporter.WriteLine();
            _reporter.WriteLine("The UDP answer was truncated (TC=1); the query was repeated over TCP.");
        }

        // Printed from the result rather than from a single attempt's notes: with retries the
        // final attempt is often not the one that carried the fallback.
        if (result.UsedEdnsFallback && !options.Json)
        {
            _reporter.WriteLine();

            if (result.Final.IsSuccess)
            {
                _reporter.WriteWarning(
                    "The query failed while carrying an EDNS(0) OPT record, but the same query without "
                    + "EDNS succeeded. Something on this path does not tolerate EDNS - a firewall, a "
                    + "middlebox, or an old resolver. Use --no-edns against this server.");
            }
            else
            {
                _reporter.WriteLine(
                    "The query was also retried without EDNS(0) and failed again, so EDNS is probably "
                    + "not the cause.");
            }
        }

        int exitCode = DetermineExitCode(result.Final);

        IReadOnlyList<string> observations = Observations.ForAttempt(result.Final, context);

        if (options.Json)
        {
            JsonOutput.WriteQuery(
                result.Final, context, exitCode, result.UsedEdnsFallback, result.UsedTcpFallback, observations);
            return exitCode;
        }

        _reporter.WriteAttempt(result.Final, context, options.Verbose, options.Debug);
        _reporter.WriteObservations(observations);
        _reporter.WriteAttemptSummary(result.Final, context);
        return exitCode;
    }

    private async Task<int> RunRepeatedAsync(
        ProbeOptions options,
        DnsQueryRequest request,
        ProbeContext context,
        CancellationToken cancellationToken)
    {
        var statistics = new QueryStatistics();
        var firstAnswerTtls = new List<uint>();
        bool anyAuthoritative = false;
        DnsQueryAttempt? last = null;

        if (!options.Json)
        {
            _reporter.WriteLine();
        }

        for (int i = 1; i <= options.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DnsQueryResult result = await _client
                .QueryAsync(request, options.Retries, options.TcpFallback, cancellationToken)
                .ConfigureAwait(false);

            last = result.Final;
            statistics.Record(result.Final);

            if (result.Final.Response is { Answers.Count: > 0 } answered)
            {
                firstAnswerTtls.Add(answered.Answers[0].TimeToLive);

                if (answered.Header.AuthoritativeAnswer)
                {
                    anyAuthoritative = true;
                }
            }

            if (!options.Json)
            {
                _reporter.WriteQueryLine(i, result.Final);
            }

            if (i < options.Count && options.IntervalMilliseconds > 0)
            {
                try
                {
                    await Task.Delay(options.IntervalMilliseconds, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        int exitCode = statistics.Received == 0
            ? ExitCodes.NoResponse
            : last is not null ? DetermineExitCode(last) : ExitCodes.NoResponse;

        var observations = new List<string>(
            Observations.ForRepeatedQueries(firstAnswerTtls, options.IntervalMilliseconds, anyAuthoritative));

        if (last is not null)
        {
            observations.AddRange(Observations.ForAttempt(last, context));
        }

        if (options.Json)
        {
            JsonOutput.WriteStatistics(statistics, context, exitCode, observations);
            return exitCode;
        }

        _reporter.WriteStatistics(statistics);

        if (options.Verbose && last is not null)
        {
            _reporter.WriteLine();
            _reporter.WriteLine("Last response");
            _reporter.WriteAttempt(last, context, options.Verbose, options.Debug);
        }

        _reporter.WriteObservations(observations);
        _reporter.WriteStatisticsSummary(statistics, context);
        return exitCode;
    }

    private async Task<int> RunCompareAsync(
        ProbeOptions options,
        IReadOnlyList<InterfaceInfo> interfaces,
        ProbeContext context,
        CancellationToken cancellationToken)
    {
        if (!options.Json)
        {
            _reporter.WriteLine();
            _reporter.WriteLine("Comparing every eligible interface against " + context.Server);
        }

        var comparer = new InterfaceComparer(_client);

        IReadOnlyList<ComparisonRow> rows = await comparer.RunAsync(
            interfaces,
            context.WireName,
            context.RecordType,
            context.Server,
            context.Family,
            context.Transport,
            options.TimeoutMilliseconds,
            !options.NoRecursion,
            !options.NoUnicastInterface,
            cancellationToken,
            context.Edns).ConfigureAwait(false);

        if (rows.Count == 0)
        {
            return Fail(
                options,
                $"No interface has an {(context.Family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address to send the query from.",
                ExitCodes.NoResponse);
        }

        int exitCode = ExitCodes.NoResponse;

        foreach (ComparisonRow row in rows)
        {
            if (row.Result == "SUCCESS")
            {
                exitCode = ExitCodes.Success;
                break;
            }
        }

        if (options.Json)
        {
            JsonOutput.WriteComparison(rows, context, exitCode);
            return exitCode;
        }

        _reporter.WriteComparisonTable(rows);
        _reporter.WriteComparisonSummary(rows, context.Server);
        return exitCode;
    }

    private void RunRouteCheck(ProbeContext context, IReadOnlyList<InterfaceInfo> interfaces)
    {
        bool ok = _routeInspector.TryGetBestRoute(
            context.Server.Address,
            context.SourceAddress,
            out RouteInfo? route,
            out string? routeError);

        int? bestInterface = null;
        if (_routeInspector.TryGetBestInterfaceIndex(context.Server.Address, out int index, out _))
        {
            bestInterface = index;
        }

        IReadOnlyList<string> warnings = ok
            ? _routeInspector.Analyse(context.Interface, context.InterfaceIndex, context.SourceAddress, context.Server.Address, route)
            : Array.Empty<string>();

        _reporter.WriteRouteCheck(context, route, routeError, bestInterface, interfaces, warnings);
    }

    /// <summary>
    /// Chooses the DNS server. When an interface was explicitly selected, only that interface's
    /// configured servers are considered - a server from another adapter is never used silently.
    /// </summary>
    private static bool TryResolveServer(
        ProbeOptions options,
        InterfaceSelectionResult selection,
        IReadOnlyList<InterfaceInfo> interfaces,
        AddressFamily family,
        out IPEndPoint? server,
        out string source,
        out string? error)
    {
        server = null;
        source = string.Empty;
        error = null;

        if (options.ServerAddress is not null)
        {
            if (options.ServerAddress.AddressFamily != family)
            {
                error = $"The DNS server {options.ServerAddress} does not match the selected address family "
                        + $"({(family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")}).";
                return false;
            }

            server = new IPEndPoint(options.ServerAddress, options.ServerPort);
            source = "command line (--server)";
            return true;
        }

        if (selection.Interface is InterfaceInfo nic)
        {
            IPAddress? candidate = FirstOfFamily(nic.DnsServers, family);

            if (candidate is null)
            {
                error = $"Interface \"{nic.Name}\" has no "
                        + $"{(family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} DNS server configured. "
                        + "Specify one explicitly with --server. DnsProbe will not fall back to another interface's "
                        + "DNS server, because that would defeat the purpose of selecting an interface.";
                return false;
            }

            server = new IPEndPoint(candidate, options.ServerPort);
            source = $"DNS configuration of {nic.Name}";
            return true;
        }

        // No interface pinned: use the system configuration, preferring an adapter with a default gateway.
        InterfaceInfo? best = null;
        foreach (InterfaceInfo candidateNic in interfaces)
        {
            if (!candidateNic.IsUp || candidateNic.IsLoopback)
            {
                continue;
            }

            if (FirstOfFamily(candidateNic.DnsServers, family) is null)
            {
                continue;
            }

            if (best is null || (candidateNic.Gateways.Count > 0 && best.Gateways.Count == 0))
            {
                best = candidateNic;
            }
        }

        if (best is null)
        {
            error = $"No {(family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} DNS server is configured on this "
                    + "machine. Specify one with --server <ip>.";
            return false;
        }

        server = new IPEndPoint(FirstOfFamily(best.DnsServers, family)!, options.ServerPort);
        source = $"system DNS configuration of {best.Name}";
        return true;
    }

    private static IPAddress? FirstOfFamily(IReadOnlyList<IPAddress> addresses, AddressFamily family)
    {
        foreach (IPAddress address in addresses)
        {
            if (address.AddressFamily == family)
            {
                return address;
            }
        }

        return null;
    }

    /// <summary>Reports a fatal problem in whichever format the user asked for.</summary>
    private int Fail(ProbeOptions options, string message, int exitCode)
    {
        if (options.Json)
        {
            JsonOutput.WriteError(message, exitCode);
        }
        else
        {
            _reporter.WriteError(message);
        }

        return exitCode;
    }

    private static int DetermineExitCode(DnsQueryAttempt attempt)
    {
        if (!attempt.IsSuccess)
        {
            return attempt.Outcome == DnsQueryOutcome.ConfigurationError ? ExitCodes.UsageError : ExitCodes.NoResponse;
        }

        return attempt.Response!.Header.ResponseCode == DnsResponseCode.NoError
            ? ExitCodes.Success
            : ExitCodes.DnsError;
    }
}
