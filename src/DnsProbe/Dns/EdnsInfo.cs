using System.Globalization;
using System.Text;

namespace DnsProbe.Dns;

/// <summary>
/// What the client asks for in the OPT pseudo-record of a query (RFC 6891).
/// </summary>
public sealed class EdnsOptions
{
    /// <summary>
    /// 1232 bytes is the widely agreed safe default: it stays below the smallest MTU that IPv6
    /// guarantees, so a DNS response never has to be fragmented. Fragmented DNS is both a
    /// reliability and a security problem, which is why bigger is not better here.
    /// </summary>
    public const ushort DefaultUdpPayloadSize = 1232;

    public const ushort MinimumUdpPayloadSize = 512;

    public const ushort MaximumUdpPayloadSize = 4096;

    /// <summary>A query with no OPT record at all - plain RFC 1035 behaviour.</summary>
    public static readonly EdnsOptions Disabled = new() { Enabled = false };

    public bool Enabled { get; init; } = true;

    public ushort UdpPayloadSize { get; init; } = DefaultUdpPayloadSize;

    /// <summary>The DO bit: asks the server to include DNSSEC records (RRSIG, NSEC, ...).</summary>
    public bool DnssecOk { get; init; }

    /// <summary>Asks the responding server to identify itself (NSID, RFC 5001).</summary>
    public bool RequestNsid { get; init; }

    /// <summary>The effective buffer size to allocate for a UDP response.</summary>
    public int ReceiveBufferSize =>
        Enabled ? Math.Max(UdpPayloadSize, MinimumUdpPayloadSize) : MinimumUdpPayloadSize;
}

/// <summary>An EDNS option that was present in the response but is not decoded structurally.</summary>
public sealed class EdnsUnknownOption
{
    public EdnsUnknownOption(ushort code, byte[] data)
    {
        Code = code;
        Data = data;
    }

    public ushort Code { get; }

    public byte[] Data { get; }

    public string Describe() =>
        $"option {Code} ({Data.Length} bytes: {Convert.ToHexString(Data)})";
}

/// <summary>
/// The OPT record found in a response, decoded.
/// </summary>
public sealed class EdnsResponse
{
    /// <summary>EDNS option code for NSID (RFC 5001).</summary>
    public const ushort OptionNsid = 3;

    /// <summary>EDNS option code for Extended DNS Errors (RFC 8914).</summary>
    public const ushort OptionExtendedError = 15;

    /// <summary>The DO bit inside the 16 flag bits of the OPT TTL field.</summary>
    private const ushort FlagDnssecOk = 0x8000;

    public required ushort UdpPayloadSize { get; init; }

    public required byte Version { get; init; }

    /// <summary>The upper 8 bits of the 12 bit extended RCODE.</summary>
    public required byte ExtendedRcodeHigh { get; init; }

    public required bool DnssecOk { get; init; }

    /// <summary>Server identifier, when NSID was requested and the server answered.</summary>
    public string? Nsid { get; init; }

    public ushort? ExtendedErrorCode { get; init; }

    public string? ExtendedErrorText { get; init; }

    public IReadOnlyList<EdnsUnknownOption> OtherOptions { get; init; } = Array.Empty<EdnsUnknownOption>();

    /// <summary>
    /// Combines the 4 bit header RCODE with the 8 extra bits carried in the OPT record.
    /// </summary>
    public int FullResponseCode(DnsResponseCode headerCode) => (ExtendedRcodeHigh << 4) | (int)headerCode;

    public string DescribeFullResponseCode(DnsResponseCode headerCode)
    {
        int full = FullResponseCode(headerCode);

        return full switch
        {
            <= 15 => headerCode.ToDisplayString(),
            16 => "BADVERS",
            17 => "BADKEY",
            18 => "BADTIME",
            19 => "BADMODE",
            20 => "BADNAME",
            21 => "BADALG",
            22 => "BADTRUNC",
            23 => "BADCOOKIE",
            _ => "RCODE" + full.ToString(CultureInfo.InvariantCulture),
        };
    }

    public string? DescribeExtendedError()
    {
        if (ExtendedErrorCode is not ushort code)
        {
            return null;
        }

        string name = ExtendedErrorName(code);
        string text = string.IsNullOrWhiteSpace(ExtendedErrorText) ? string.Empty : $" - {ExtendedErrorText}";

        return $"{code} ({name}){text}";
    }

    /// <summary>Names from the IANA Extended DNS Error Codes registry (RFC 8914).</summary>
    private static string ExtendedErrorName(ushort code) => code switch
    {
        0 => "Other",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        _ => "unassigned",
    };

    /// <summary>
    /// Finds the OPT record in the additional section and decodes it. Returns null when the
    /// server did not answer with EDNS, which is itself a useful diagnostic.
    /// </summary>
    public static EdnsResponse? TryExtract(IReadOnlyList<DnsRecord> additionals, IList<string> warnings)
    {
        foreach (DnsRecord record in additionals)
        {
            if (record.Type != DnsRecordType.OPT)
            {
                continue;
            }

            // OPT reuses the header fields for other purposes: CLASS carries the advertised UDP
            // payload size and TTL carries the extended RCODE, the version and the flags.
            ushort payloadSize = (ushort)record.Class;
            uint ttl = record.TimeToLive;

            byte extendedRcodeHigh = (byte)((ttl >> 24) & 0xFF);
            byte version = (byte)((ttl >> 16) & 0xFF);
            ushort flags = (ushort)(ttl & 0xFFFF);

            string? nsid = null;
            ushort? errorCode = null;
            string? errorText = null;
            var others = new List<EdnsUnknownOption>();

            ParseOptions(record.RawData, warnings, ref nsid, ref errorCode, ref errorText, others);

            if (version != 0)
            {
                warnings.Add($"The server answered with EDNS version {version}; only version 0 is defined.");
            }

            return new EdnsResponse
            {
                UdpPayloadSize = payloadSize,
                Version = version,
                ExtendedRcodeHigh = extendedRcodeHigh,
                DnssecOk = (flags & FlagDnssecOk) != 0,
                Nsid = nsid,
                ExtendedErrorCode = errorCode,
                ExtendedErrorText = errorText,
                OtherOptions = others,
            };
        }

        return null;
    }

    /// <summary>
    /// Walks the option list inside the OPT RDATA. Every length is checked against the remaining
    /// buffer before it is used, so a hostile or truncated option list cannot read out of bounds.
    /// </summary>
    private static void ParseOptions(
        byte[] rdata,
        IList<string> warnings,
        ref string? nsid,
        ref ushort? errorCode,
        ref string? errorText,
        List<EdnsUnknownOption> others)
    {
        int offset = 0;

        while (offset < rdata.Length)
        {
            if (offset + 4 > rdata.Length)
            {
                warnings.Add("The OPT record ends in the middle of an option header; the rest was ignored.");
                return;
            }

            ushort code = (ushort)((rdata[offset] << 8) | rdata[offset + 1]);
            int length = (rdata[offset + 2] << 8) | rdata[offset + 3];
            offset += 4;

            if (length < 0 || offset + length > rdata.Length)
            {
                warnings.Add($"EDNS option {code} claims {length} bytes but the record is shorter; the rest was ignored.");
                return;
            }

            byte[] data = new byte[length];
            Array.Copy(rdata, offset, data, 0, length);
            offset += length;

            switch (code)
            {
                case OptionNsid:
                    nsid = DescribeNsid(data);
                    break;

                case OptionExtendedError when length >= 2:
                    errorCode = (ushort)((data[0] << 8) | data[1]);
                    errorText = length > 2
                        ? SafeText(data.AsSpan(2).ToArray())
                        : null;
                    break;

                case OptionExtendedError:
                    warnings.Add("The Extended DNS Error option is shorter than its mandatory 2 byte code.");
                    break;

                default:
                    others.Add(new EdnsUnknownOption(code, data));
                    break;
            }
        }
    }

    /// <summary>
    /// NSID is defined as opaque bytes, but servers almost always put readable text there.
    /// Printable payloads are shown as text and anything else as hex.
    /// </summary>
    private static string DescribeNsid(byte[] data)
    {
        if (data.Length == 0)
        {
            return "(empty)";
        }

        foreach (byte value in data)
        {
            if (value < 0x20 || value > 0x7E)
            {
                return Convert.ToHexString(data);
            }
        }

        return Encoding.ASCII.GetString(data);
    }

    /// <summary>Escapes control characters so a hostile response cannot rewrite the terminal.</summary>
    private static string SafeText(byte[] data)
    {
        string decoded = Encoding.UTF8.GetString(data);
        var builder = new StringBuilder(decoded.Length);

        foreach (char character in decoded)
        {
            if (char.IsControl(character))
            {
                builder.Append(CultureInfo.InvariantCulture, $"\\{(int)character:000}");
            }
            else
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }
}
