namespace DnsProbe.Dns;

/// <summary>Fixed 12 byte DNS header (RFC 1035 section 4.1.1).</summary>
public sealed class DnsHeader
{
    public ushort Id { get; init; }

    public bool IsResponse { get; init; }

    public DnsOpCode OpCode { get; init; }

    public bool AuthoritativeAnswer { get; init; }

    public bool Truncated { get; init; }

    public bool RecursionDesired { get; init; }

    public bool RecursionAvailable { get; init; }

    public bool AuthenticData { get; init; }

    public bool CheckingDisabled { get; init; }

    public DnsResponseCode ResponseCode { get; init; }

    public ushort QuestionCount { get; init; }

    public ushort AnswerCount { get; init; }

    public ushort AuthorityCount { get; init; }

    public ushort AdditionalCount { get; init; }

    /// <summary>Renders the header flags the way dig does, e.g. "qr rd ra".</summary>
    public string FlagsString()
    {
        var flags = new List<string>(6);
        if (IsResponse) flags.Add("qr");
        if (AuthoritativeAnswer) flags.Add("aa");
        if (Truncated) flags.Add("tc");
        if (RecursionDesired) flags.Add("rd");
        if (RecursionAvailable) flags.Add("ra");
        if (AuthenticData) flags.Add("ad");
        if (CheckingDisabled) flags.Add("cd");
        return flags.Count == 0 ? "-" : string.Join(' ', flags);
    }
}

/// <summary>A single entry of the DNS question section.</summary>
public sealed class DnsQuestion
{
    public DnsQuestion(string name, DnsRecordType type, DnsRecordClass recordClass)
    {
        Name = name;
        Type = type;
        Class = recordClass;
    }

    public string Name { get; }

    public DnsRecordType Type { get; }

    public DnsRecordClass Class { get; }

    public override string ToString() => $"{Name} {Class.ToDisplayString()} {Type.ToDisplayString()}";
}

/// <summary>A decoded DNS message.</summary>
public sealed class DnsMessage
{
    public DnsMessage(
        DnsHeader header,
        IReadOnlyList<DnsQuestion> questions,
        IReadOnlyList<DnsRecord> answers,
        IReadOnlyList<DnsRecord> authorities,
        IReadOnlyList<DnsRecord> additionals,
        IReadOnlyList<string> warnings,
        EdnsResponse? edns = null)
    {
        Header = header;
        Questions = questions;
        Answers = answers;
        Authorities = authorities;
        Additionals = additionals;
        Warnings = warnings;
        Edns = edns;
    }

    public DnsHeader Header { get; }

    public IReadOnlyList<DnsQuestion> Questions { get; }

    public IReadOnlyList<DnsRecord> Answers { get; }

    public IReadOnlyList<DnsRecord> Authorities { get; }

    public IReadOnlyList<DnsRecord> Additionals { get; }

    /// <summary>
    /// Non fatal problems found while decoding (for example a single record whose RDATA
    /// did not match its declared type). The message is still usable.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>The decoded OPT record, or null when the server answered without EDNS.</summary>
    public EdnsResponse? Edns { get; }

    public bool HasWarnings => Warnings.Count > 0;

    /// <summary>
    /// The response code including the 8 extra bits an OPT record can carry. Without EDNS this
    /// is just the 4 bit header value.
    /// </summary>
    public string ResponseCodeDisplay() =>
        Edns is null
            ? Header.ResponseCode.ToDisplayString()
            : Edns.DescribeFullResponseCode(Header.ResponseCode);
}
