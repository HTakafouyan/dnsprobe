using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace DnsProbe.Dns;

/// <summary>
/// Decodes DNS messages received from the network.
/// </summary>
/// <remarks>
/// Everything in this class assumes the input is hostile:
/// <list type="bullet">
/// <item>every multi-byte read is bounds checked before it happens,</item>
/// <item>RDLENGTH is validated against the remaining buffer before the RDATA is touched,</item>
/// <item>the record cursor is always advanced by RDLENGTH, never by however far an RDATA
/// decoder happened to read, so a lying RDATA cannot desynchronise the parser,</item>
/// <item>a single undecodable RDATA degrades to a <see cref="RawRecord"/> plus a warning
/// instead of failing the whole message,</item>
/// <item>section counts from the header are never trusted as allocation sizes; parsing stops
/// when the buffer is exhausted.</item>
/// </list>
/// </remarks>
public static class DnsPacketParser
{
    /// <summary>
    /// Parses a complete DNS message.
    /// </summary>
    /// <exception cref="DnsProtocolException">The message is too damaged to be interpreted at all.</exception>
    public static DnsMessage Parse(ReadOnlySpan<byte> message)
    {
        if (message.Length < DnsPacketBuilder.HeaderLength)
        {
            throw new DnsProtocolException(
                $"Malformed DNS message: {message.Length} bytes received, at least {DnsPacketBuilder.HeaderLength} are required for the header.");
        }

        var warnings = new List<string>();

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(message[..2]);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2));
        ushort questionCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        ushort answerCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2));
        ushort authorityCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(8, 2));
        ushort additionalCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(10, 2));

        var header = new DnsHeader
        {
            Id = id,
            IsResponse = (flags & 0x8000) != 0,
            OpCode = (DnsOpCode)((flags >> 11) & 0x0F),
            AuthoritativeAnswer = (flags & 0x0400) != 0,
            Truncated = (flags & 0x0200) != 0,
            RecursionDesired = (flags & 0x0100) != 0,
            RecursionAvailable = (flags & 0x0080) != 0,
            AuthenticData = (flags & 0x0020) != 0,
            CheckingDisabled = (flags & 0x0010) != 0,
            ResponseCode = (DnsResponseCode)(flags & 0x000F),
            QuestionCount = questionCount,
            AnswerCount = answerCount,
            AuthorityCount = authorityCount,
            AdditionalCount = additionalCount,
        };

        int offset = DnsPacketBuilder.HeaderLength;

        var questions = new List<DnsQuestion>(Math.Min((int)questionCount, 16));
        var answers = new List<DnsRecord>(Math.Min((int)answerCount, 32));
        var authorities = new List<DnsRecord>(Math.Min((int)authorityCount, 32));
        var additionals = new List<DnsRecord>(Math.Min((int)additionalCount, 32));

        try
        {
            for (int i = 0; i < questionCount; i++)
            {
                questions.Add(ReadQuestion(message, ref offset));
            }

            ReadRecords(message, ref offset, answerCount, answers, warnings, "answer");
            ReadRecords(message, ref offset, authorityCount, authorities, warnings, "authority");
            ReadRecords(message, ref offset, additionalCount, additionals, warnings, "additional");
        }
        catch (DnsProtocolException ex)
        {
            // Keep whatever was decoded successfully; report the rest as a warning.
            // Truncated (TC=1) UDP responses legitimately end up here.
            warnings.Add($"Stopped decoding at offset {offset}: {ex.Message}");
        }

        EdnsResponse? edns = EdnsResponse.TryExtract(additionals, warnings);

        return new DnsMessage(header, questions, answers, authorities, additionals, warnings, edns);
    }

    /// <summary>Parses a message and never throws; returns null on unrecoverable damage.</summary>
    public static bool TryParse(ReadOnlySpan<byte> message, out DnsMessage? result, out string? error)
    {
        try
        {
            result = Parse(message);
            error = null;
            return true;
        }
        catch (DnsProtocolException ex)
        {
            result = null;
            error = ex.Message;
            return false;
        }
    }

    private static DnsQuestion ReadQuestion(ReadOnlySpan<byte> message, ref int offset)
    {
        string name = DnsName.Read(message, ref offset);
        EnsureAvailable(message, offset, 4, "question type/class");

        var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        var cls = (DnsRecordClass)BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        offset += 4;

        return new DnsQuestion(name, type, cls);
    }

    private static void ReadRecords(
        ReadOnlySpan<byte> message,
        ref int offset,
        int count,
        List<DnsRecord> target,
        List<string> warnings,
        string sectionName)
    {
        for (int i = 0; i < count; i++)
        {
            if (offset >= message.Length)
            {
                warnings.Add($"The {sectionName} section declares {count} records but the message ended after {i}.");
                return;
            }

            target.Add(ReadRecord(message, ref offset, warnings, sectionName));
        }
    }

    private static DnsRecord ReadRecord(
        ReadOnlySpan<byte> message,
        ref int offset,
        List<string> warnings,
        string sectionName)
    {
        string name = DnsName.Read(message, ref offset);

        EnsureAvailable(message, offset, 10, "resource record header");

        var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        var cls = (DnsRecordClass)BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        uint ttl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(offset + 4, 4));
        int rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));
        offset += 10;

        EnsureAvailable(message, offset, rdLength, $"RDATA of a {type.ToDisplayString()} record");

        int rdataStart = offset;
        byte[] rdata = message.Slice(rdataStart, rdLength).ToArray();

        // The cursor advances by RDLENGTH no matter what the RDATA decoder does.
        offset = rdataStart + rdLength;

        try
        {
            return DecodeRecord(message, name, type, cls, ttl, rdata, rdataStart, rdLength);
        }
        catch (DnsProtocolException ex)
        {
            warnings.Add($"Could not decode a {type.ToDisplayString()} record in the {sectionName} section: {ex.Message}");
            return new RawRecord(name, type, cls, ttl, rdata, ex.Message);
        }
    }

    private static DnsRecord DecodeRecord(
        ReadOnlySpan<byte> message,
        string name,
        DnsRecordType type,
        DnsRecordClass cls,
        uint ttl,
        byte[] rdata,
        int rdataStart,
        int rdLength)
    {
        int rdataEnd = rdataStart + rdLength;

        switch (type)
        {
            case DnsRecordType.A:
            {
                if (rdLength != 4)
                {
                    throw new DnsProtocolException($"an A record must carry 4 bytes of RDATA, got {rdLength}.");
                }

                return new AddressRecord(name, type, cls, ttl, rdata, new IPAddress(rdata));
            }

            case DnsRecordType.AAAA:
            {
                if (rdLength != 16)
                {
                    throw new DnsProtocolException($"an AAAA record must carry 16 bytes of RDATA, got {rdLength}.");
                }

                return new AddressRecord(name, type, cls, ttl, rdata, new IPAddress(rdata));
            }

            case DnsRecordType.NS:
            case DnsRecordType.CNAME:
            case DnsRecordType.PTR:
            {
                int cursor = rdataStart;
                string target = DnsName.Read(message, ref cursor);
                EnsureConsumedWithinRdata(cursor, rdataEnd, type);
                return new DomainNameRecord(name, type, cls, ttl, rdata, target);
            }

            case DnsRecordType.MX:
            {
                if (rdLength < 3)
                {
                    throw new DnsProtocolException($"an MX record needs at least 3 bytes of RDATA, got {rdLength}.");
                }

                ushort preference = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(rdataStart, 2));
                int cursor = rdataStart + 2;
                string exchange = DnsName.Read(message, ref cursor);
                EnsureConsumedWithinRdata(cursor, rdataEnd, type);
                return new MxRecord(name, cls, ttl, rdata, preference, exchange);
            }

            case DnsRecordType.SRV:
            {
                if (rdLength < 7)
                {
                    throw new DnsProtocolException($"an SRV record needs at least 7 bytes of RDATA, got {rdLength}.");
                }

                ushort priority = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(rdataStart, 2));
                ushort weight = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(rdataStart + 2, 2));
                ushort port = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(rdataStart + 4, 2));
                int cursor = rdataStart + 6;
                string target = DnsName.Read(message, ref cursor);
                EnsureConsumedWithinRdata(cursor, rdataEnd, type);
                return new SrvRecord(name, cls, ttl, rdata, priority, weight, port, target);
            }

            case DnsRecordType.SOA:
            {
                int cursor = rdataStart;
                string primary = DnsName.Read(message, ref cursor);
                string mailbox = DnsName.Read(message, ref cursor);

                if (cursor + 20 > rdataEnd)
                {
                    throw new DnsProtocolException("the SOA record is missing its 20 bytes of numeric fields.");
                }

                uint serial = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(cursor, 4));
                int refresh = BinaryPrimitives.ReadInt32BigEndian(message.Slice(cursor + 4, 4));
                int retry = BinaryPrimitives.ReadInt32BigEndian(message.Slice(cursor + 8, 4));
                int expire = BinaryPrimitives.ReadInt32BigEndian(message.Slice(cursor + 12, 4));
                uint minimum = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(cursor + 16, 4));

                return new SoaRecord(name, cls, ttl, rdata, primary, mailbox, serial, refresh, retry, expire, minimum);
            }

            case DnsRecordType.TXT:
            {
                var strings = new List<string>();
                int cursor = 0;

                while (cursor < rdata.Length)
                {
                    int length = rdata[cursor];
                    cursor++;

                    if (cursor + length > rdata.Length)
                    {
                        throw new DnsProtocolException("a TXT character-string extends past the end of the RDATA.");
                    }

                    strings.Add(DecodeCharacterString(rdata.AsSpan(cursor, length)));
                    cursor += length;
                }

                return new TxtRecord(name, cls, ttl, rdata, strings);
            }

            default:
                return new RawRecord(name, type, cls, ttl, rdata);
        }
    }

    private static void EnsureConsumedWithinRdata(int cursor, int rdataEnd, DnsRecordType type)
    {
        if (cursor > rdataEnd)
        {
            throw new DnsProtocolException(
                $"the name inside the {type.ToDisplayString()} RDATA extends past the declared RDLENGTH.");
        }
    }

    private static string DecodeCharacterString(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
        {
            if (b is >= 0x20 and <= 0x7E)
            {
                builder.Append((char)b);
            }
            else
            {
                builder.Append('\\').Append(b.ToString("000", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static void EnsureAvailable(ReadOnlySpan<byte> message, int offset, int required, string what)
    {
        if (required < 0)
        {
            throw new DnsProtocolException($"Malformed DNS message: negative length for {what}.");
        }

        if (offset < 0 || offset > message.Length || message.Length - offset < required)
        {
            throw new DnsProtocolException(
                $"Malformed DNS message: {required} bytes are needed at offset {offset} for the {what}, "
                + $"but only {Math.Max(0, message.Length - offset)} bytes remain.");
        }
    }
}
