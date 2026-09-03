using System.Net;
using System.Net.Sockets;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Runs the same DNS query from every eligible interface so that the user can see at a glance
/// which paths can reach the server and how fast they are.
/// </summary>
public sealed class InterfaceComparer
{
    private readonly DnsClient _client;

    public InterfaceComparer(DnsClient client)
    {
        _client = client;
    }

    /// <summary>An interface takes part in the comparison when it is up and has an address of the right family.</summary>
    public static bool IsEligible(InterfaceInfo nic, AddressFamily family) =>
        nic.IsUp
        && !nic.IsLoopback
        && nic.IndexFor(family) != 0
        && nic.PreferredSourceAddress(family) is not null;

    /// <summary>
    /// Host-internal virtual switches - Hyper-V, WSL, Docker, VMware, VirtualBox - exist to connect
    /// the host to guests, not to anything outside. They have no route to an external DNS server and
    /// never will, so testing them produces a guaranteed failure that carries no information and
    /// clutters both the table and the diagnosis. They are skipped unless --compare-all is given.
    /// </summary>
    public static bool IsHostInternalVirtual(InterfaceInfo nic) =>
        nic.Category is InterfaceCategory.HyperV
            or InterfaceCategory.ContainerOrWsl
            or InterfaceCategory.VirtualMachine;

    public async Task<IReadOnlyList<ComparisonRow>> RunAsync(
        IReadOnlyList<InterfaceInfo> interfaces,
        string wireName,
        DnsRecordType recordType,
        IPEndPoint server,
        AddressFamily family,
        DnsTransport transport,
        int timeoutMilliseconds,
        bool recursionDesired,
        bool useUnicastInterfaceOption,
        CancellationToken cancellationToken,
        EdnsOptions? edns = null,
        bool includeVirtual = false,
        List<string>? skipped = null)
    {
        var rows = new List<ComparisonRow>();

        foreach (InterfaceInfo nic in interfaces)
        {
            if (!IsEligible(nic, family))
            {
                continue;
            }

            if (!includeVirtual && IsHostInternalVirtual(nic))
            {
                skipped?.Add($"{nic.Name} ({nic.CategoryLabel})");
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();

            IPAddress source = nic.PreferredSourceAddress(family)!;
            int index = nic.IndexFor(family);

            var request = new DnsQueryRequest
            {
                Name = wireName,
                RecordType = recordType,
                Server = server,
                Binding = new SocketBinding(family, transport == DnsTransport.Tcp ? ProtocolType.Tcp : ProtocolType.Udp,
                    source, index, useUnicastInterfaceOption),
                TimeoutMilliseconds = timeoutMilliseconds,
                RecursionDesired = recursionDesired,
                Transport = transport,
                Edns = edns,
            };

            DnsQueryResult result = await _client
                .QueryAsync(request, retries: 0, tcpFallback: false, cancellationToken)
                .ConfigureAwait(false);

            DnsQueryAttempt attempt = result.Final;

            string outcome;
            double? rtt = null;
            string? detail = null;

            if (attempt.IsSuccess)
            {
                DnsResponseCode code = attempt.Response!.Header.ResponseCode;
                outcome = code == DnsResponseCode.NoError ? "SUCCESS" : code.ToDisplayString();
                rtt = attempt.RoundTripTime.TotalMilliseconds;

                if (code == DnsResponseCode.NoError && attempt.Response.Answers.Count > 0)
                {
                    detail = attempt.Response.Answers[0].Value;
                }
                else if (code != DnsResponseCode.NoError)
                {
                    detail = code.Explain();
                }
            }
            else
            {
                outcome = DiagnosticReporter.DescribeOutcome(attempt.Outcome);
                detail = attempt.ErrorMessage;
            }

            rows.Add(new ComparisonRow
            {
                InterfaceName = nic.Name,
                SourceAddress = source.ToString(),
                Result = outcome,
                RoundTripMilliseconds = rtt,
                Detail = detail,
            });
        }

        return rows;
    }
}
