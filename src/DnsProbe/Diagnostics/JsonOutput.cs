using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Emits a single JSON document instead of human readable output, so that dnsprobe can be used
/// from monitoring scripts.
///
/// The shape is deliberately stable and flat-ish: every document has "tool", "timestamp" and
/// "status", and the rest depends on what was run. Consumers should key off "status" and
/// "exitCode" rather than parsing prose.
/// </summary>
public static class JsonOutput
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    private static void Write(object document) =>
        Console.Out.WriteLine(JsonSerializer.Serialize(document, Options));

    private static string Timestamp() => DateTimeOffset.UtcNow.ToString("O");

    // ---------------------------------------------------------------- errors

    public static void WriteError(string message, int exitCode)
    {
        Write(new
        {
            tool = "dnsprobe",
            version = Cli.HelpText.Version,
            timestamp = Timestamp(),
            status = "error",
            exitCode,
            error = message,
        });
    }

    // ---------------------------------------------------------------- interfaces

    public static void WriteInterfaces(IReadOnlyList<InterfaceInfo> interfaces, bool showAll)
    {
        var list = new List<object>();

        foreach (InterfaceInfo nic in interfaces)
        {
            if (!showAll && (nic.IsLoopback || !nic.IsUp))
            {
                continue;
            }

            list.Add(new
            {
                name = nic.Name,
                description = nic.Description,
                id = nic.Id,
                kind = nic.CategoryLabel,
                type = nic.Type.ToString(),
                status = nic.Status.ToString(),
                isUp = nic.IsUp,
                ipv4Index = nic.Ipv4Index,
                ipv6Index = nic.Ipv6Index,
                ipv4 = Strings(nic.Ipv4Addresses),
                ipv6 = Strings(nic.Ipv6Addresses),
                gateways = Strings(nic.Gateways),
                dnsServers = Strings(nic.DnsServers),
            });
        }

        Write(new
        {
            tool = "dnsprobe",
            version = Cli.HelpText.Version,
            timestamp = Timestamp(),
            status = "ok",
            exitCode = 0,
            interfaces = list,
        });
    }

    // ---------------------------------------------------------------- single query

    public static void WriteQuery(
        DnsQueryAttempt attempt,
        ProbeContext context,
        int exitCode,
        bool usedEdnsFallback = false,
        bool usedTcpFallback = false,
        IReadOnlyList<string>? observations = null)
    {
        Write(new
        {
            tool = "dnsprobe",
            version = Cli.HelpText.Version,
            timestamp = Timestamp(),
            status = attempt.IsSuccess ? "ok" : "failed",
            exitCode,
            query = QueryBlock(context),
            probe = ProbeBlock(context),
            fallbacks = new
            {
                edns = usedEdnsFallback,
                tcp = usedTcpFallback,
            },
            response = ResponseBlock(attempt),
            observations = observations ?? Array.Empty<string>(),
        });
    }

    // ---------------------------------------------------------------- repeated queries

    public static void WriteStatistics(
        QueryStatistics statistics,
        ProbeContext context,
        int exitCode,
        IReadOnlyList<string>? observations = null)
    {
        Write(new
        {
            tool = "dnsprobe",
            version = Cli.HelpText.Version,
            timestamp = Timestamp(),
            status = statistics.Received > 0 ? "ok" : "failed",
            exitCode,
            query = QueryBlock(context),
            probe = ProbeBlock(context),
            statistics = new
            {
                sent = statistics.Sent,
                received = statistics.Received,
                lost = statistics.Lost,
                lossPercent = Round(statistics.LossPercentage),
                minMs = Round(statistics.Minimum),
                maxMs = Round(statistics.Maximum),
                averageMs = Round(statistics.Average),
                jitterMs = Round(statistics.Jitter),
            },
            observations = observations ?? Array.Empty<string>(),
        });
    }

    // ---------------------------------------------------------------- compare

    public static void WriteComparison(IReadOnlyList<ComparisonRow> rows, ProbeContext context, int exitCode)
    {
        var list = new List<object>();
        int succeeded = 0;

        foreach (ComparisonRow row in rows)
        {
            bool ok = string.Equals(row.Result, "SUCCESS", StringComparison.Ordinal);
            if (ok)
            {
                succeeded++;
            }

            list.Add(new
            {
                interfaceName = row.InterfaceName,
                sourceIp = row.SourceAddress,
                result = row.Result,
                success = ok,
                roundTripMs = Round(row.RoundTripMilliseconds),
                detail = row.Detail,
            });
        }

        Write(new
        {
            tool = "dnsprobe",
            version = Cli.HelpText.Version,
            timestamp = Timestamp(),
            status = succeeded > 0 ? "ok" : "failed",
            exitCode,
            query = QueryBlock(context),
            server = context.Server.Address.ToString(),
            serverPort = context.Server.Port,
            interfacesTested = rows.Count,
            interfacesSucceeded = succeeded,
            results = list,
        });
    }

    // ---------------------------------------------------------------- shared blocks

    private static object QueryBlock(ProbeContext context) => new
    {
        name = context.QueryName,
        wireName = context.WireName,
        type = context.RecordType.ToDisplayString(),
        transport = context.Transport.ToString().ToUpperInvariant(),
        addressFamily = context.Family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4",
    };

    private static object ProbeBlock(ProbeContext context) => new
    {
        interfaceName = context.Interface?.Name,
        interfaceIndex = context.InterfaceIndex,
        sourceIp = context.SourceAddress?.ToString(),
        interfacePinned = context.UnicastInterfaceOptionUsed,
        server = context.Server.Address.ToString(),
        serverPort = context.Server.Port,
        serverSource = context.ServerSource,
        timeoutMs = context.TimeoutMilliseconds,
        retries = context.Retries,
        edns = context.Edns is null || !context.Edns.Enabled
            ? null
            : new
            {
                udpPayloadSize = context.Edns.UdpPayloadSize,
                dnssecOk = context.Edns.DnssecOk,
                nsidRequested = context.Edns.RequestNsid,
            },
    };

    private static object ResponseBlock(DnsQueryAttempt attempt)
    {
        if (!attempt.IsSuccess)
        {
            return new
            {
                received = false,
                outcome = DiagnosticReporter.DescribeOutcome(attempt.Outcome),
                error = attempt.ErrorMessage,
                socketError = attempt.SocketError?.ToString(),
                localEndPoint = attempt.LocalEndPoint?.ToString(),
                remoteEndPoint = attempt.RemoteEndPoint?.ToString(),
                notes = attempt.Notes,
            };
        }

        DnsMessage response = attempt.Response!;

        return new
        {
            received = true,
            outcome = "SUCCESS",
            roundTripMs = Round(attempt.RoundTripTime.TotalMilliseconds),
            transactionId = $"0x{attempt.TransactionId:X4}",
            transport = attempt.Transport.ToString().ToUpperInvariant(),
            responseCode = response.ResponseCodeDisplay(),
            flags = response.Header.FlagsString(),
            authoritative = response.Header.AuthoritativeAnswer,
            truncated = response.Header.Truncated,
            recursionAvailable = response.Header.RecursionAvailable,
            counts = new
            {
                question = (int)response.Header.QuestionCount,
                answer = (int)response.Header.AnswerCount,
                authority = (int)response.Header.AuthorityCount,
                additional = (int)response.Header.AdditionalCount,
            },
            edns = EdnsBlock(response),
            answers = Records(response.Answers),
            authorities = Records(response.Authorities),
            additionals = Records(response.Additionals),
            localEndPoint = attempt.LocalEndPoint?.ToString(),
            remoteEndPoint = attempt.RemoteEndPoint?.ToString(),
            warnings = response.Warnings,
            notes = attempt.Notes,
        };
    }

    private static object? EdnsBlock(DnsMessage response)
    {
        if (response.Edns is not EdnsResponse edns)
        {
            return null;
        }

        return new
        {
            version = (int)edns.Version,
            udpPayloadSize = (int)edns.UdpPayloadSize,
            dnssecOk = edns.DnssecOk,
            nsid = edns.Nsid,
            extendedErrorCode = edns.ExtendedErrorCode,
            extendedError = edns.DescribeExtendedError(),
        };
    }

    private static List<object> Records(IReadOnlyList<DnsRecord> records)
    {
        var list = new List<object>(records.Count);

        foreach (DnsRecord record in records)
        {
            // The OPT pseudo-record is reported in the "edns" object instead.
            if (record.Type == DnsRecordType.OPT)
            {
                continue;
            }

            list.Add(new
            {
                name = record.Name,
                type = record.Type.ToDisplayString(),
                ttl = record.TimeToLive,
                value = record.Value,
            });
        }

        return list;
    }

    private static List<string> Strings(IReadOnlyList<IPAddress> addresses)
    {
        var list = new List<string>(addresses.Count);

        foreach (IPAddress address in addresses)
        {
            list.Add(address.ToString());
        }

        return list;
    }

    private static double? Round(double? value) =>
        value is double actual ? Math.Round(actual, 2) : null;

    private static double Round(double value) => Math.Round(value, 2);
}
