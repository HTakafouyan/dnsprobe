using System.Buffers.Binary;
using System.Net;
using DnsProbe.Dns;
using Xunit;

namespace DnsProbe.Tests;

public class DnsPacketBuilderTests
{
    [Fact]
    public void BuildQuery_WritesHeaderAndQuestionForARecord()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(0xA31F, "example.com", DnsRecordType.A);

        Assert.Equal(0xA31F, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(0, 2)));
        Assert.Equal(0x0100, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2))); // RD
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2)));      // QDCOUNT
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)));      // ANCOUNT

        // 12 header + (7 example) + (3 com) + root + 4
        Assert.Equal(12 + 1 + 7 + 1 + 3 + 1 + 4, packet.Length);

        Assert.Equal(7, packet[12]);
        Assert.Equal((byte)'e', packet[13]);

        int questionEnd = packet.Length - 4;
        Assert.Equal((ushort)DnsRecordType.A, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(questionEnd, 2)));
        Assert.Equal((ushort)DnsRecordClass.IN, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(questionEnd + 2, 2)));
    }

    [Theory]
    [InlineData(DnsRecordType.AAAA)]
    [InlineData(DnsRecordType.MX)]
    [InlineData(DnsRecordType.TXT)]
    [InlineData(DnsRecordType.NS)]
    [InlineData(DnsRecordType.SOA)]
    public void BuildQuery_EncodesRequestedType(DnsRecordType type)
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(1, "example.com", type);
        int questionEnd = packet.Length - 4;

        Assert.Equal((ushort)type, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(questionEnd, 2)));
    }

    [Fact]
    public void BuildQuery_ForPtrUsesReverseName()
    {
        string reverse = DnsName.ToReverseLookupName(IPAddress.Parse("8.8.4.4"));
        byte[] packet = DnsPacketBuilder.BuildQuery(1, reverse, DnsRecordType.PTR);

        int offset = 12;
        string decoded = DnsName.Read(packet, ref offset);

        Assert.Equal("4.4.8.8.in-addr.arpa.", decoded);
        Assert.Equal((ushort)DnsRecordType.PTR, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2)));
    }

    [Fact]
    public void BuildQuery_WithoutRecursionClearsRdFlag()
    {
        byte[] packet = DnsPacketBuilder.BuildQuery(1, "example.com", DnsRecordType.A, recursionDesired: false);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2)));
    }

    [Fact]
    public void BuildQuery_RejectsOverlongLabel()
    {
        string label = new string('a', 64);
        Assert.Throws<DnsProtocolException>(() => DnsPacketBuilder.BuildQuery(1, label + ".com", DnsRecordType.A));
    }

    [Fact]
    public void BuildQuery_RejectsEmptyLabel()
    {
        Assert.Throws<DnsProtocolException>(() => DnsPacketBuilder.BuildQuery(1, "example..com", DnsRecordType.A));
    }

    [Fact]
    public void BuildQuery_RejectsOverlongName()
    {
        string longName = string.Join('.', Enumerable.Repeat(new string('a', 60), 5));
        Assert.Throws<DnsProtocolException>(() => DnsPacketBuilder.BuildQuery(1, longName, DnsRecordType.A));
    }

    [Fact]
    public void FrameForTcp_PrependsBigEndianLength()
    {
        byte[] message = DnsPacketBuilder.BuildQuery(1, "example.com", DnsRecordType.A);
        byte[] framed = DnsPacketBuilder.FrameForTcp(message);

        Assert.Equal(message.Length + 2, framed.Length);
        Assert.Equal(message.Length, BinaryPrimitives.ReadUInt16BigEndian(framed.AsSpan(0, 2)));
        Assert.Equal(message[0], framed[2]);
    }

    [Fact]
    public void CreateTransactionId_ProducesVaryingValues()
    {
        var seen = new HashSet<ushort>();
        for (int i = 0; i < 50; i++)
        {
            seen.Add(DnsPacketBuilder.CreateTransactionId());
        }

        // 50 draws out of 65536 values: collisions are possible, all-identical is not.
        Assert.True(seen.Count > 1);
    }
}
