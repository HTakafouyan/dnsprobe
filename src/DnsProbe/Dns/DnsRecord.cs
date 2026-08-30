using System.Globalization;
using System.Net;
using System.Text;

namespace DnsProbe.Dns;

/// <summary>Base class of every decoded resource record.</summary>
public abstract class DnsRecord
{
    protected DnsRecord(string name, DnsRecordType type, DnsRecordClass recordClass, uint timeToLive, byte[] rawData)
    {
        Name = name;
        Type = type;
        Class = recordClass;
        TimeToLive = timeToLive;
        RawData = rawData;
    }

    public string Name { get; }

    public DnsRecordType Type { get; }

    public DnsRecordClass Class { get; }

    public uint TimeToLive { get; }

    /// <summary>The raw RDATA bytes exactly as received.</summary>
    public byte[] RawData { get; }

    /// <summary>Human readable RDATA representation.</summary>
    public abstract string Value { get; }

    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture,
            $"{Name} {TimeToLive} {Class.ToDisplayString()} {Type.ToDisplayString()} {Value}");
}

/// <summary>A or AAAA record.</summary>
public sealed class AddressRecord : DnsRecord
{
    public AddressRecord(string name, DnsRecordType type, DnsRecordClass recordClass, uint ttl, byte[] rawData, IPAddress address)
        : base(name, type, recordClass, ttl, rawData)
    {
        Address = address;
    }

    public IPAddress Address { get; }

    public override string Value => Address.ToString();
}

/// <summary>CNAME, NS or PTR record - a record whose RDATA is a single domain name.</summary>
public sealed class DomainNameRecord : DnsRecord
{
    public DomainNameRecord(string name, DnsRecordType type, DnsRecordClass recordClass, uint ttl, byte[] rawData, string target)
        : base(name, type, recordClass, ttl, rawData)
    {
        Target = target;
    }

    public string Target { get; }

    public override string Value => Target;
}

/// <summary>MX record.</summary>
public sealed class MxRecord : DnsRecord
{
    public MxRecord(string name, DnsRecordClass recordClass, uint ttl, byte[] rawData, ushort preference, string exchange)
        : base(name, DnsRecordType.MX, recordClass, ttl, rawData)
    {
        Preference = preference;
        Exchange = exchange;
    }

    public ushort Preference { get; }

    public string Exchange { get; }

    public override string Value => string.Create(CultureInfo.InvariantCulture, $"{Preference} {Exchange}");
}

/// <summary>TXT record - one or more character strings.</summary>
public sealed class TxtRecord : DnsRecord
{
    public TxtRecord(string name, DnsRecordClass recordClass, uint ttl, byte[] rawData, IReadOnlyList<string> strings)
        : base(name, DnsRecordType.TXT, recordClass, ttl, rawData)
    {
        Strings = strings;
    }

    public IReadOnlyList<string> Strings { get; }

    public override string Value
    {
        get
        {
            var builder = new StringBuilder();
            foreach (string s in Strings)
            {
                if (builder.Length > 0)
                {
                    builder.Append(' ');
                }

                builder.Append('"').Append(s.Replace("\\", "\\\\", StringComparison.Ordinal)
                    .Replace("\"", "\\\"", StringComparison.Ordinal)).Append('"');
            }

            return builder.ToString();
        }
    }
}

/// <summary>SOA record.</summary>
public sealed class SoaRecord : DnsRecord
{
    public SoaRecord(
        string name,
        DnsRecordClass recordClass,
        uint ttl,
        byte[] rawData,
        string primaryNameServer,
        string responsibleMailbox,
        uint serial,
        int refresh,
        int retry,
        int expire,
        uint minimum)
        : base(name, DnsRecordType.SOA, recordClass, ttl, rawData)
    {
        PrimaryNameServer = primaryNameServer;
        ResponsibleMailbox = responsibleMailbox;
        Serial = serial;
        Refresh = refresh;
        Retry = retry;
        Expire = expire;
        Minimum = minimum;
    }

    public string PrimaryNameServer { get; }

    public string ResponsibleMailbox { get; }

    public uint Serial { get; }

    public int Refresh { get; }

    public int Retry { get; }

    public int Expire { get; }

    public uint Minimum { get; }

    public override string Value => string.Create(
        CultureInfo.InvariantCulture,
        $"{PrimaryNameServer} {ResponsibleMailbox} {Serial} {Refresh} {Retry} {Expire} {Minimum}");
}

/// <summary>SRV record.</summary>
public sealed class SrvRecord : DnsRecord
{
    public SrvRecord(string name, DnsRecordClass recordClass, uint ttl, byte[] rawData, ushort priority, ushort weight, ushort port, string target)
        : base(name, DnsRecordType.SRV, recordClass, ttl, rawData)
    {
        Priority = priority;
        Weight = weight;
        Port = port;
        Target = target;
    }

    public ushort Priority { get; }

    public ushort Weight { get; }

    public ushort Port { get; }

    public string Target { get; }

    public override string Value =>
        string.Create(CultureInfo.InvariantCulture, $"{Priority} {Weight} {Port} {Target}");
}

/// <summary>
/// Any record whose type is not specifically supported, or a record whose RDATA
/// could not be decoded. The raw bytes are always preserved.
/// </summary>
public sealed class RawRecord : DnsRecord
{
    public RawRecord(string name, DnsRecordType type, DnsRecordClass recordClass, uint ttl, byte[] rawData, string? parseError = null)
        : base(name, type, recordClass, ttl, rawData)
    {
        ParseError = parseError;
    }

    /// <summary>Set when the RDATA was malformed for its declared type.</summary>
    public string? ParseError { get; }

    public override string Value
    {
        get
        {
            string hex = Convert.ToHexString(RawData);
            return ParseError is null
                ? string.Create(CultureInfo.InvariantCulture, $"\\# {RawData.Length} {hex}")
                : string.Create(CultureInfo.InvariantCulture, $"\\# {RawData.Length} {hex}  (undecodable: {ParseError})");
        }
    }
}
