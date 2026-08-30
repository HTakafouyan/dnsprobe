using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DnsProbe.Dns;

/// <summary>
/// Builds DNS query messages on the wire format. No compression is used in queries
/// (there is nothing to compress in a single question section).
/// </summary>
public static class DnsPacketBuilder
{
    public const int HeaderLength = 12;

    private const ushort FlagRecursionDesired = 0x0100;

    /// <summary>Generates a cryptographically random transaction ID.</summary>
    public static ushort CreateTransactionId() => (ushort)RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);

    /// <summary>
    /// Builds a standard query message.
    /// </summary>
    /// <param name="transactionId">The DNS transaction ID that the response must echo.</param>
    /// <param name="name">Query name in presentation format.</param>
    /// <param name="type">Query type.</param>
    /// <param name="recursionDesired">Whether the RD flag should be set.</param>
    /// <param name="recordClass">Query class, normally IN.</param>
    /// <param name="edns">EDNS(0) options, or null / disabled for a plain RFC 1035 query.</param>
    public static byte[] BuildQuery(
        ushort transactionId,
        string name,
        DnsRecordType type,
        bool recursionDesired = true,
        DnsRecordClass recordClass = DnsRecordClass.IN,
        EdnsOptions? edns = null)
    {
        byte[] encodedName = DnsName.Encode(name);
        byte[] optRecord = BuildOptRecord(edns);

        byte[] packet = new byte[HeaderLength + encodedName.Length + 4 + optRecord.Length];

        Span<byte> span = packet;

        BinaryPrimitives.WriteUInt16BigEndian(span[..2], transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(2, 2), recursionDesired ? FlagRecursionDesired : (ushort)0);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(4, 2), 1); // QDCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(6, 2), 0); // ANCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(8, 2), 0); // NSCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(10, 2), optRecord.Length > 0 ? (ushort)1 : (ushort)0); // ARCOUNT

        encodedName.CopyTo(span[HeaderLength..]);

        int offset = HeaderLength + encodedName.Length;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, 2), (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset + 2, 2), (ushort)recordClass);
        offset += 4;

        if (optRecord.Length > 0)
        {
            optRecord.CopyTo(span[offset..]);
        }

        return packet;
    }

    /// <summary>
    /// Builds the OPT pseudo-record for the additional section (RFC 6891 section 6.1.2).
    ///
    /// OPT reuses the ordinary record header for other purposes: the CLASS field carries the
    /// advertised UDP payload size and the TTL field carries the extended RCODE, the EDNS
    /// version and the flags. The owner name is always the root label.
    /// </summary>
    private static byte[] BuildOptRecord(EdnsOptions? edns)
    {
        if (edns is null || !edns.Enabled)
        {
            return Array.Empty<byte>();
        }

        byte[] optionData = BuildOptionData(edns);

        // 1 (root name) + 2 type + 2 class + 4 ttl + 2 rdlength
        byte[] record = new byte[11 + optionData.Length];
        Span<byte> span = record;

        span[0] = 0; // root name
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(1, 2), (ushort)DnsRecordType.OPT);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(3, 2), edns.UdpPayloadSize);

        // TTL: extended-rcode (0) | version (0) | flags
        uint flags = edns.DnssecOk ? 0x0000_8000u : 0u;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(5, 4), flags);

        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(9, 2), (ushort)optionData.Length);

        if (optionData.Length > 0)
        {
            optionData.CopyTo(span[11..]);
        }

        return record;
    }

    private static byte[] BuildOptionData(EdnsOptions edns)
    {
        if (!edns.RequestNsid)
        {
            return Array.Empty<byte>();
        }

        // NSID is requested with a zero length option (RFC 5001 section 2.3).
        byte[] data = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(0, 2), EdnsResponse.OptionNsid);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2, 2), 0);
        return data;
    }

    /// <summary>
    /// Wraps a DNS message in the two byte big endian length prefix required by DNS over TCP
    /// (RFC 1035 section 4.2.2).
    /// </summary>
    public static byte[] FrameForTcp(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (message.Length > ushort.MaxValue)
        {
            throw new DnsProtocolException($"DNS message of {message.Length} bytes is too large for TCP framing.");
        }

        byte[] framed = new byte[message.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)message.Length);
        message.CopyTo(framed, 2);
        return framed;
    }
}
