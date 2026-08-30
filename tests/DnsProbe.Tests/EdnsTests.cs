using System.Text;
using DnsProbe.Dns;
using Xunit;

namespace DnsProbe.Tests;

public class EdnsTests
{
    private static byte[] BuildOptRdata(params (ushort Code, byte[] Data)[] options)
    {
        var bytes = new List<byte>();

        foreach ((ushort code, byte[] data) in options)
        {
            bytes.Add((byte)(code >> 8));
            bytes.Add((byte)(code & 0xFF));
            bytes.Add((byte)(data.Length >> 8));
            bytes.Add((byte)(data.Length & 0xFF));
            bytes.AddRange(data);
        }

        return bytes.ToArray();
    }

    /// <summary>Builds a response carrying one OPT record in the additional section.</summary>
    private static byte[] BuildResponseWithOpt(ushort payloadSize, uint ttl, byte[] rdata)
    {
        var writer = new PacketWriter();
        writer.WriteHeader(0x1234, Flags.StandardResponse, questions: 1, answers: 0, authorities: 0, additionals: 1);
        writer.WriteQuestion("example.com", DnsRecordType.A, DnsRecordClass.IN);

        // OPT record: root name, type 41, class = payload size, ttl = flags.
        writer.WriteByte(0);
        writer.WriteUInt16((ushort)DnsRecordType.OPT);
        writer.WriteUInt16(payloadSize);
        writer.WriteUInt32(ttl);
        writer.WriteUInt16((ushort)rdata.Length);
        writer.WriteBytes(rdata);

        return writer.ToArray();
    }

    // ---------------------------------------------------------------- building

    [Fact]
    public void BuildQuery_WithoutEdns_HasNoAdditionalRecord()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(1, "example.com", DnsRecordType.A);

        Assert.Equal(0, (packet[10] << 8) | packet[11]);
    }

    [Fact]
    public void BuildQuery_WithEdns_AppendsOptRecord()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(
            1,
            "example.com",
            DnsRecordType.A,
            edns: new EdnsOptions { UdpPayloadSize = 1232 });

        // ARCOUNT must be 1.
        Assert.Equal(1, (packet[10] << 8) | packet[11]);

        // The OPT record is the last 11 bytes: root name, type, class, ttl, rdlength.
        int offset = packet.Length - 11;
        Assert.Equal(0, packet[offset]);
        Assert.Equal((ushort)DnsRecordType.OPT, (ushort)((packet[offset + 1] << 8) | packet[offset + 2]));
        Assert.Equal(1232, (packet[offset + 3] << 8) | packet[offset + 4]);
        Assert.Equal(0, (packet[offset + 9] << 8) | packet[offset + 10]); // RDLENGTH
    }

    [Fact]
    public void BuildQuery_WithDnssecOk_SetsDoBit()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(
            1,
            "example.com",
            DnsRecordType.A,
            edns: new EdnsOptions { DnssecOk = true });

        int offset = packet.Length - 11;
        uint ttl = (uint)((packet[offset + 5] << 24)
                          | (packet[offset + 6] << 16)
                          | (packet[offset + 7] << 8)
                          | packet[offset + 8]);

        Assert.Equal(0x8000u, ttl & 0xFFFFu);
        Assert.Equal(0u, (ttl >> 16) & 0xFFu); // version must be 0
    }

    [Fact]
    public void BuildQuery_WithNsid_AddsZeroLengthOption()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(
            1,
            "example.com",
            DnsRecordType.A,
            edns: new EdnsOptions { RequestNsid = true });

        // 11 byte OPT header plus a 4 byte zero length option.
        int offset = packet.Length - 15;
        Assert.Equal(4, (packet[offset + 9] << 8) | packet[offset + 10]); // RDLENGTH
        Assert.Equal(EdnsResponse.OptionNsid, (ushort)((packet[offset + 11] << 8) | packet[offset + 12]));
        Assert.Equal(0, (packet[offset + 13] << 8) | packet[offset + 14]);
    }

    // ---------------------------------------------------------------- parsing

    [Fact]
    public void Parse_ExtractsPayloadSizeAndFlags()
    {
        byte[] packet = BuildResponseWithOpt(4096, 0x0000_8000, Array.Empty<byte>());

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.NotNull(message.Edns);
        Assert.Equal(4096, message.Edns!.UdpPayloadSize);
        Assert.Equal(0, message.Edns.Version);
        Assert.True(message.Edns.DnssecOk);
    }

    [Fact]
    public void Parse_WithoutOptRecord_LeavesEdnsNull()
    {
        var writer = new PacketWriter();
        writer.WriteHeader(0x1234, Flags.StandardResponse, questions: 1, answers: 0, authorities: 0, additionals: 0);
        writer.WriteQuestion("example.com", DnsRecordType.A, DnsRecordClass.IN);

        DnsMessage message = DnsPacketParser.Parse(writer.ToArray());

        Assert.Null(message.Edns);
    }

    [Fact]
    public void Parse_ReadsNsidAsText()
    {
        byte[] rdata = BuildOptRdata((EdnsResponse.OptionNsid, Encoding.ASCII.GetBytes("dns-node-7")));
        byte[] packet = BuildResponseWithOpt(1232, 0, rdata);

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.Equal("dns-node-7", message.Edns!.Nsid);
    }

    [Fact]
    public void Parse_ReadsExtendedError()
    {
        byte[] payload = new byte[] { 0x00, 0x06 }
            .Concat(Encoding.UTF8.GetBytes("signature failed"))
            .ToArray();

        byte[] packet = BuildResponseWithOpt(1232, 0, BuildOptRdata((EdnsResponse.OptionExtendedError, payload)));

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.Equal((ushort)6, message.Edns!.ExtendedErrorCode);
        Assert.Equal("signature failed", message.Edns.ExtendedErrorText);
        Assert.Contains("DNSSEC Bogus", message.Edns.DescribeExtendedError());
    }

    [Fact]
    public void Parse_ExtendedRcodeIsCombinedWithHeaderRcode()
    {
        // Extended RCODE high byte = 1 gives 1 << 4 | 0 = 16 = BADVERS.
        byte[] packet = BuildResponseWithOpt(1232, 0x0100_0000, Array.Empty<byte>());

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.Equal(16, message.Edns!.FullResponseCode(DnsResponseCode.NoError));
        Assert.Equal("BADVERS", message.ResponseCodeDisplay());
    }

    [Fact]
    public void Parse_LyingOptionLengthDoesNotThrow()
    {
        // An option that claims 200 bytes but supplies none.
        byte[] rdata = new byte[] { 0x00, 0x03, 0x00, 0xC8 };
        byte[] packet = BuildResponseWithOpt(1232, 0, rdata);

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.NotNull(message.Edns);
        Assert.Contains(message.Warnings, warning => warning.Contains("EDNS option", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_TruncatedOptionHeaderIsReportedNotThrown()
    {
        byte[] rdata = new byte[] { 0x00, 0x03 };
        byte[] packet = BuildResponseWithOpt(1232, 0, rdata);

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.NotNull(message.Edns);
        Assert.NotEmpty(message.Warnings);
    }

    [Fact]
    public void Parse_UnknownOptionIsPreserved()
    {
        byte[] rdata = BuildOptRdata((12345, new byte[] { 0xDE, 0xAD }));
        byte[] packet = BuildResponseWithOpt(1232, 0, rdata);

        DnsMessage message = DnsPacketParser.Parse(packet);

        Assert.Single(message.Edns!.OtherOptions);
        Assert.Equal(12345, message.Edns.OtherOptions[0].Code);
    }

    // ---------------------------------------------------------------- options object

    [Fact]
    public void ReceiveBufferSize_NeverGoesBelowFiveHundredTwelve()
    {
        var edns = new EdnsOptions { UdpPayloadSize = 512 };

        Assert.Equal(512, edns.ReceiveBufferSize);
        Assert.Equal(512, EdnsOptions.Disabled.ReceiveBufferSize);
    }
}
