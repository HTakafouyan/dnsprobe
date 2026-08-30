using System.Net;
using DnsProbe.Dns;
using Xunit;

namespace DnsProbe.Tests;

public class DnsPacketParserTests
{
    private static byte[] SimpleAResponse(DnsResponseCode code = DnsResponseCode.NoError, ushort extraFlags = 0)
    {
        var writer = new PacketWriter();
        ushort flags = Flags.WithRcode((ushort)(Flags.StandardResponse | extraFlags), code);

        writer.WriteHeader(0x1234, flags, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.A);

        writer.WriteRecord(
            w => w.WritePointer(12),
            DnsRecordType.A,
            300,
            w => w.WriteBytes(93, 184, 216, 34));

        return writer.ToArray();
    }

    [Fact]
    public void Parse_ReadsHeaderFlagsAndAnswer()
    {
        DnsMessage message = DnsPacketParser.Parse(SimpleAResponse());

        Assert.Equal(0x1234, message.Header.Id);
        Assert.True(message.Header.IsResponse);
        Assert.True(message.Header.RecursionDesired);
        Assert.True(message.Header.RecursionAvailable);
        Assert.False(message.Header.Truncated);
        Assert.Equal(DnsResponseCode.NoError, message.Header.ResponseCode);

        DnsQuestion question = Assert.Single(message.Questions);
        Assert.Equal("example.com.", question.Name);
        Assert.Equal(DnsRecordType.A, question.Type);

        var record = Assert.IsType<AddressRecord>(Assert.Single(message.Answers));
        Assert.Equal(IPAddress.Parse("93.184.216.34"), record.Address);
        Assert.Equal("example.com.", record.Name);
        Assert.Equal(300u, record.TimeToLive);
        Assert.Empty(message.Warnings);
    }

    [Fact]
    public void Parse_ReadsMultipleAnswers()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 3);
        writer.WriteQuestion("example.com", DnsRecordType.A);

        for (int i = 1; i <= 3; i++)
        {
            byte last = (byte)i;
            writer.WriteRecord(w => w.WritePointer(12), DnsRecordType.A, 60, w => w.WriteBytes(10, 0, 0, last));
        }

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Equal(3, message.Answers.Count);
        Assert.Equal("10.0.0.3", ((AddressRecord)message.Answers[2]).Address.ToString());
    }

    [Fact]
    public void Parse_FollowsCnameChainWithCompression()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 2);
        writer.WriteQuestion("www.example.com", DnsRecordType.A);

        int targetOffset = 0;

        writer.WriteRecord(
            w => w.WritePointer(12),
            DnsRecordType.CNAME,
            120,
            w =>
            {
                targetOffset = w.Position;
                w.WriteName("cdn.example.net");
            });

        writer.WriteRecord(
            w => w.WritePointer(targetOffset),
            DnsRecordType.A,
            120,
            w => w.WriteBytes(203, 0, 113, 5));

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        var cname = Assert.IsType<DomainNameRecord>(message.Answers[0]);
        Assert.Equal("cdn.example.net.", cname.Target);

        var address = Assert.IsType<AddressRecord>(message.Answers[1]);
        Assert.Equal("cdn.example.net.", address.Name);
        Assert.Equal("203.0.113.5", address.Address.ToString());
    }

    [Fact]
    public void Parse_ReadsMxRecord()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.MX);
        writer.WriteRecord(
            w => w.WritePointer(12),
            DnsRecordType.MX,
            3600,
            w =>
            {
                w.WriteUInt16(10);
                w.WriteName("mail.example.com");
            });

        var mx = Assert.IsType<MxRecord>(Assert.Single(DnsPacketParser.Parse(writer.ToArray()).Answers));

        Assert.Equal(10, mx.Preference);
        Assert.Equal("mail.example.com.", mx.Exchange);
        Assert.Equal("10 mail.example.com.", mx.Value);
    }

    [Fact]
    public void Parse_ReadsTxtRecordWithMultipleStrings()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.TXT);
        writer.WriteRecord(
            w => w.WritePointer(12),
            DnsRecordType.TXT,
            60,
            w =>
            {
                w.WriteByte(5).WriteBytes(System.Text.Encoding.ASCII.GetBytes("hello"));
                w.WriteByte(5).WriteBytes(System.Text.Encoding.ASCII.GetBytes("world"));
            });

        var txt = Assert.IsType<TxtRecord>(Assert.Single(DnsPacketParser.Parse(writer.ToArray()).Answers));

        Assert.Equal(2, txt.Strings.Count);
        Assert.Equal("hello", txt.Strings[0]);
        Assert.Equal("world", txt.Strings[1]);
    }

    [Fact]
    public void Parse_ReadsSoaRecord()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 0, authorities: 1);
        writer.WriteQuestion("example.com", DnsRecordType.SOA);
        writer.WriteRecord(
            w => w.WritePointer(12),
            DnsRecordType.SOA,
            900,
            w =>
            {
                w.WriteName("ns1.example.com");
                w.WriteName("hostmaster.example.com");
                w.WriteUInt32(2024010101);
                w.WriteUInt32(7200);
                w.WriteUInt32(3600);
                w.WriteUInt32(1209600);
                w.WriteUInt32(300);
            });

        var soa = Assert.IsType<SoaRecord>(Assert.Single(DnsPacketParser.Parse(writer.ToArray()).Authorities));

        Assert.Equal("ns1.example.com.", soa.PrimaryNameServer);
        Assert.Equal("hostmaster.example.com.", soa.ResponsibleMailbox);
        Assert.Equal(2024010101u, soa.Serial);
        Assert.Equal(300u, soa.Minimum);
    }

    [Fact]
    public void Parse_ReadsPtrRecord()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("8.8.8.8.in-addr.arpa", DnsRecordType.PTR);
        writer.WriteRecord(w => w.WritePointer(12), DnsRecordType.PTR, 60, w => w.WriteName("dns.google"));

        var ptr = Assert.IsType<DomainNameRecord>(Assert.Single(DnsPacketParser.Parse(writer.ToArray()).Answers));
        Assert.Equal("dns.google.", ptr.Target);
    }

    [Theory]
    [InlineData(DnsResponseCode.NXDomain, "NXDOMAIN")]
    [InlineData(DnsResponseCode.ServFail, "SERVFAIL")]
    [InlineData(DnsResponseCode.Refused, "REFUSED")]
    [InlineData(DnsResponseCode.FormErr, "FORMERR")]
    [InlineData(DnsResponseCode.NotImp, "NOTIMP")]
    public void Parse_ReadsResponseCodes(DnsResponseCode code, string display)
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.WithRcode(Flags.StandardResponse, code), 1, 0);
        writer.WriteQuestion("example.com", DnsRecordType.A);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Equal(code, message.Header.ResponseCode);
        Assert.Equal(display, message.Header.ResponseCode.ToDisplayString());
        Assert.Empty(message.Answers);
    }

    [Fact]
    public void Parse_DetectsTruncatedFlag()
    {
        DnsMessage message = DnsPacketParser.Parse(SimpleAResponse(extraFlags: Flags.Truncated));
        Assert.True(message.Header.Truncated);
    }

    [Fact]
    public void Parse_TruncatedPayloadKeepsHeaderAndReportsWarning()
    {
        byte[] full = SimpleAResponse();
        byte[] cut = full.AsSpan(0, full.Length - 6).ToArray();

        DnsMessage message = DnsPacketParser.Parse(cut);

        Assert.Equal(DnsResponseCode.NoError, message.Header.ResponseCode);
        Assert.Empty(message.Answers);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_RejectsMessageShorterThanHeader()
    {
        Assert.Throws<DnsProtocolException>(() => DnsPacketParser.Parse(new byte[5]));
    }

    [Fact]
    public void Parse_RejectsForwardCompressionPointer()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 0);
        writer.WritePointer(200); // points forward, outside the message
        writer.WriteUInt16((ushort)DnsRecordType.A);
        writer.WriteUInt16((ushort)DnsRecordClass.IN);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Empty(message.Questions);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_RejectsSelfReferencingPointerLoop()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 0);
        writer.WritePointer(12); // the pointer sits at offset 12 and points to itself
        writer.WriteUInt16((ushort)DnsRecordType.A);
        writer.WriteUInt16((ushort)DnsRecordClass.IN);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Empty(message.Questions);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_RejectsMutualPointerLoop()
    {
        // Two pointers referring to each other. The "must point strictly backwards" rule
        // makes one of them illegal, so parsing stops instead of looping forever.
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 0);
        writer.WritePointer(14); // offset 12 -> 14
        writer.WritePointer(12); // offset 14 -> 12
        writer.WriteUInt16((ushort)DnsRecordType.A);
        writer.WriteUInt16((ushort)DnsRecordClass.IN);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Empty(message.Questions);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_RejectsReservedLabelType()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 0);
        writer.WriteByte(0x80); // reserved label type 0b10
        writer.WriteByte(0x00);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_RdLengthLongerThanBufferIsRejected()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.A);
        writer.WritePointer(12);
        writer.WriteUInt16((ushort)DnsRecordType.A);
        writer.WriteUInt16((ushort)DnsRecordClass.IN);
        writer.WriteUInt32(60);
        writer.WriteUInt16(500); // lies about the RDATA length
        writer.WriteBytes(1, 2, 3, 4);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Empty(message.Answers);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_WrongRdLengthForAddressRecordDegradesToRawRecord()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.A);
        writer.WriteRecord(w => w.WritePointer(12), DnsRecordType.A, 60, w => w.WriteBytes(1, 2, 3)); // only 3 bytes

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        var raw = Assert.IsType<RawRecord>(Assert.Single(message.Answers));
        Assert.NotNull(raw.ParseError);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_UnknownRecordTypeIsPreservedAsRawData()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(1, Flags.StandardResponse, 1, 1);
        writer.WriteQuestion("example.com", DnsRecordType.A);
        writer.WriteRecord(w => w.WritePointer(12), (DnsRecordType)9999, 60, w => w.WriteBytes(0xDE, 0xAD));

        var raw = Assert.IsType<RawRecord>(Assert.Single(DnsPacketParser.Parse(writer.ToArray()).Answers));

        Assert.Null(raw.ParseError);
        Assert.Equal(new byte[] { 0xDE, 0xAD }, raw.RawData);
    }

    [Fact]
    public void TryParse_ReturnsFalseInsteadOfThrowing()
    {
        Assert.False(DnsPacketParser.TryParse(new byte[3], out DnsMessage? message, out string? error));
        Assert.Null(message);
        Assert.NotNull(error);
    }

    [Fact]
    public void Parse_NeverThrowsOnRandomGarbage()
    {
        var random = new Random(20240115);

        for (int i = 0; i < 500; i++)
        {
            byte[] data = new byte[random.Next(12, 600)];
            random.NextBytes(data);

            // Must not throw anything other than DnsProtocolException.
            try
            {
                DnsPacketParser.Parse(data);
            }
            catch (DnsProtocolException)
            {
                // acceptable
            }
        }
    }
}
