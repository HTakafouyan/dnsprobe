namespace DnsProbe.Dns;

/// <summary>DNS resource record types (RFC 1035 and successors).</summary>
public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    CAA = 257,
    ANY = 255,
}

/// <summary>DNS resource record classes.</summary>
public enum DnsRecordClass : ushort
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
}

/// <summary>DNS header OPCODE field.</summary>
public enum DnsOpCode : byte
{
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

/// <summary>DNS header RCODE field (4 bit values only - EDNS extended rcodes are not used).</summary>
public enum DnsResponseCode : byte
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
}

/// <summary>Transport used to carry a DNS message.</summary>
public enum DnsTransport
{
    Udp,
    Tcp,
}

public static class DnsEnumExtensions
{
    public static string ToDisplayString(this DnsResponseCode code) => code switch
    {
        DnsResponseCode.NoError => "NOERROR",
        DnsResponseCode.FormErr => "FORMERR",
        DnsResponseCode.ServFail => "SERVFAIL",
        DnsResponseCode.NXDomain => "NXDOMAIN",
        DnsResponseCode.NotImp => "NOTIMP",
        DnsResponseCode.Refused => "REFUSED",
        DnsResponseCode.YXDomain => "YXDOMAIN",
        DnsResponseCode.YXRRSet => "YXRRSET",
        DnsResponseCode.NXRRSet => "NXRRSET",
        DnsResponseCode.NotAuth => "NOTAUTH",
        DnsResponseCode.NotZone => "NOTZONE",
        _ => $"RCODE{(byte)code}",
    };

    public static string ToDisplayString(this DnsRecordType type) =>
        Enum.IsDefined(typeof(DnsRecordType), type) ? type.ToString() : $"TYPE{(ushort)type}";

    public static string ToDisplayString(this DnsRecordClass cls) =>
        Enum.IsDefined(typeof(DnsRecordClass), cls) ? cls.ToString() : $"CLASS{(ushort)cls}";

    /// <summary>Human readable explanation of a response code, used for diagnostics.</summary>
    public static string Explain(this DnsResponseCode code) => code switch
    {
        DnsResponseCode.NoError => "The query completed successfully.",
        DnsResponseCode.FormErr => "The DNS server could not interpret the query (format error).",
        DnsResponseCode.ServFail => "The DNS server failed to process the query (SERVFAIL). "
                                    + "This is a server side failure, not a network failure.",
        DnsResponseCode.NXDomain => "The queried name does not exist (NXDOMAIN).",
        DnsResponseCode.NotImp => "The DNS server does not support the requested query type or opcode.",
        DnsResponseCode.Refused => "The DNS server refused to answer. "
                                   + "Typically an ACL: the source IP is not allowed to query this server.",
        _ => "The DNS server returned a non-zero response code.",
    };
}
