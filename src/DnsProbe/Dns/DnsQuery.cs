using System.Net;
using System.Net.Sockets;
using DnsProbe.Network;

namespace DnsProbe.Dns;

/// <summary>Everything needed to send exactly one DNS query.</summary>
public sealed class DnsQueryRequest
{
    public required string Name { get; init; }

    public required DnsRecordType RecordType { get; init; }

    public required IPEndPoint Server { get; init; }

    public required SocketBinding Binding { get; init; }

    public DnsRecordClass RecordClass { get; init; } = DnsRecordClass.IN;

    public bool RecursionDesired { get; init; } = true;

    public int TimeoutMilliseconds { get; init; } = 2000;

    public DnsTransport Transport { get; init; } = DnsTransport.Udp;

    /// <summary>EDNS(0) options. Null means no OPT record is sent.</summary>
    public EdnsOptions? Edns { get; init; }

    /// <summary>Returns the same request with EDNS switched off, for the fallback path.</summary>
    public DnsQueryRequest WithoutEdns() => new()
    {
        Name = Name,
        RecordType = RecordType,
        Server = Server,
        Binding = Binding,
        RecordClass = RecordClass,
        RecursionDesired = RecursionDesired,
        TimeoutMilliseconds = TimeoutMilliseconds,
        Transport = Transport,
        Edns = null,
    };
}

/// <summary>Coarse classification of what happened, used for exit codes and statistics.</summary>
public enum DnsQueryOutcome
{
    /// <summary>A well formed DNS response arrived (which may still carry SERVFAIL, NXDOMAIN, ...).</summary>
    Success,
    Timeout,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,

    /// <summary>
    /// The socket was pinned to an interface that has no route to the destination. Windows
    /// rejects the send with WSAEINVAL rather than with a routing error, so it needs its own
    /// outcome to avoid being reported as a generic socket malfunction.
    /// </summary>
    PinnedInterfaceUnreachable,
    AccessDenied,
    SocketFailure,
    MalformedResponse,
    ConfigurationError,
}

/// <summary>The result of a single send/receive cycle.</summary>
public sealed class DnsQueryAttempt
{
    public required DnsQueryOutcome Outcome { get; init; }

    public required DnsTransport Transport { get; init; }

    public ushort TransactionId { get; init; }

    public DnsMessage? Response { get; init; }

    public byte[]? QueryBytes { get; init; }

    public byte[]? ResponseBytes { get; init; }

    public IPEndPoint? LocalEndPoint { get; init; }

    public IPEndPoint? RemoteEndPoint { get; init; }

    public TimeSpan RoundTripTime { get; init; }

    public string? ErrorMessage { get; init; }

    public SocketError? SocketError { get; init; }

    /// <summary>Informational notes, e.g. which socket options were applied or packets that were ignored.</summary>
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();

    public bool IsSuccess => Outcome == DnsQueryOutcome.Success;

    public DnsResponseCode? ResponseCode => Response?.Header.ResponseCode;
}

/// <summary>The aggregate of all attempts made for one logical query (retries + TCP fallback).</summary>
public sealed class DnsQueryResult
{
    public DnsQueryResult(IReadOnlyList<DnsQueryAttempt> attempts, bool usedTcpFallback, bool usedEdnsFallback = false)
    {
        Attempts = attempts;
        UsedTcpFallback = usedTcpFallback;
        UsedEdnsFallback = usedEdnsFallback;
    }

    public IReadOnlyList<DnsQueryAttempt> Attempts { get; }

    public bool UsedTcpFallback { get; }

    /// <summary>True when the query had to be repeated without an EDNS(0) OPT record.</summary>
    public bool UsedEdnsFallback { get; }

    public DnsQueryAttempt Final => Attempts[^1];

    public bool IsSuccess => Final.IsSuccess;
}
