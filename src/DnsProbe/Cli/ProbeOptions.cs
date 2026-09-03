using System.Net;
using System.Net.Sockets;
using DnsProbe.Dns;

namespace DnsProbe.Cli;

/// <summary>Top level action requested on the command line.</summary>
public enum ProbeCommand
{
    Query,
    ListInterfaces,
    Help,
    Version,
    Interactive,
}

/// <summary>The fully validated command line.</summary>
public sealed class ProbeOptions
{
    public ProbeCommand Command { get; set; } = ProbeCommand.Query;

    /// <summary>The name (or IP address) exactly as the user typed it.</summary>
    public string? QueryName { get; set; }

    public DnsRecordType RecordType { get; set; } = DnsRecordType.A;

    public bool RecordTypeExplicit { get; set; }

    public string? InterfaceName { get; set; }

    public int? InterfaceIndex { get; set; }

    public IPAddress? SourceIp { get; set; }

    public IPAddress? ServerAddress { get; set; }

    public int ServerPort { get; set; } = 53;

    public bool UseSystemDns { get; set; }

    public DnsTransport Transport { get; set; } = DnsTransport.Udp;

    public bool TcpFallback { get; set; }

    public int TimeoutMilliseconds { get; set; } = 2000;

    public int Retries { get; set; } = 1;

    public int Count { get; set; } = 1;

    public int IntervalMilliseconds { get; set; } = 1000;

    public bool Verbose { get; set; }

    public bool Debug { get; set; }

    public bool RouteCheck { get; set; }

    /// <summary>
    /// Walk the delegation chain from the root servers down instead of asking one resolver.
    /// </summary>
    public bool Trace { get; set; }

    /// <summary>
    /// How many name servers to try at each level of a trace before giving up on that level.
    /// Every server for a zone holds the same data, so this only matters when servers do not answer.
    /// </summary>
    public int TraceServersPerLevel { get; set; } = DnsTracer.DefaultServersPerLevel;

    public bool Compare { get; set; }

    /// <summary>
    /// Include host-internal virtual switches (Hyper-V, WSL, Docker, VM adapters) in --compare.
    /// They are skipped by default because they cannot reach an external server by design.
    /// </summary>
    public bool CompareAll { get; set; }

    public AddressFamily? ForcedFamily { get; set; }

    /// <summary>--interfaces: also show loopback and non-operational adapters.</summary>
    public bool ShowAllInterfaces { get; set; }

    public bool AllowDownInterface { get; set; }

    /// <summary>Disables IP_UNICAST_IF / IPV6_UNICAST_IF, leaving only Socket.Bind().</summary>
    public bool NoUnicastInterface { get; set; }

    public bool NoRecursion { get; set; }

    /// <summary>Forces plain output even when the console supports ANSI colour.</summary>
    public bool NoColor { get; set; }

    /// <summary>Emit a single JSON document instead of human readable output.</summary>
    public bool Json { get; set; }

    /// <summary>Print only the answer values, one per line, and nothing else.</summary>
    public bool Short { get; set; }

    /// <summary>
    /// Query class. Almost always IN; CH is what version.bind and id.server require, so asking
    /// those questions in class IN - as this tool used to - simply gets NXDOMAIN.
    /// </summary>
    public DnsRecordClass RecordClass { get; set; } = DnsRecordClass.IN;

    /// <summary>Send an EDNS(0) OPT record. On by default.</summary>
    public bool UseEdns { get; set; } = true;

    public ushort EdnsUdpPayloadSize { get; set; } = EdnsOptions.DefaultUdpPayloadSize;

    /// <summary>Set the DO bit to request DNSSEC records. Implies EDNS.</summary>
    public bool DnssecOk { get; set; }

    /// <summary>Ask the server to identify itself (NSID). Implies EDNS.</summary>
    public bool RequestNsid { get; set; }

    /// <summary>Builds the EDNS options that go on the wire, or null when EDNS is off.</summary>
    public EdnsOptions? BuildEdnsOptions() =>
        UseEdns
            ? new EdnsOptions
            {
                Enabled = true,
                UdpPayloadSize = EdnsUdpPayloadSize,
                DnssecOk = DnssecOk,
                RequestNsid = RequestNsid,
            }
            : null;

    /// <summary>
    /// The name that actually goes on the wire. For PTR queries against an IP literal this is
    /// the in-addr.arpa / ip6.arpa form.
    /// </summary>
    public string ResolveWireName()
    {
        if (QueryName is null)
        {
            throw new InvalidOperationException("No query name was provided.");
        }

        if (RecordType == DnsRecordType.PTR && IPAddress.TryParse(QueryName, out IPAddress? address))
        {
            return DnsName.ToReverseLookupName(address);
        }

        return QueryName;
    }

    /// <summary>
    /// When the user passes a bare IP address without --type, a PTR lookup is what they meant.
    /// Returns true when the record type was adjusted.
    /// </summary>
    public bool ApplyImplicitPtr()
    {
        if (!RecordTypeExplicit && QueryName is not null && IPAddress.TryParse(QueryName, out _))
        {
            RecordType = DnsRecordType.PTR;
            return true;
        }

        return false;
    }
}
