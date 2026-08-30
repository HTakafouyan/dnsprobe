using System.Net;
using DnsProbe.Dns;
using Xunit;

namespace DnsProbe.Tests;

public class DnsNameTests
{
    [Fact]
    public void Encode_ProducesLengthPrefixedLabels()
    {
        byte[] encoded = DnsName.Encode("www.example.com");

        Assert.Equal(new byte[]
        {
            3, (byte)'w', (byte)'w', (byte)'w',
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m',
            0,
        }, encoded);
    }

    [Fact]
    public void Encode_AcceptsTrailingRootDot()
    {
        Assert.Equal(DnsName.Encode("example.com"), DnsName.Encode("example.com."));
    }

    [Fact]
    public void Encode_RootNameIsSingleZeroByte()
    {
        Assert.Equal(new byte[] { 0 }, DnsName.Encode("."));
    }

    [Fact]
    public void Encode_ConvertsUnicodeToPunycode()
    {
        byte[] encoded = DnsName.Encode("bücher.example");
        int offset = 0;
        string decoded = DnsName.Read(encoded, ref offset);

        Assert.StartsWith("xn--", decoded, StringComparison.Ordinal);
    }

    [Fact]
    public void TryValidate_ReportsProblemsWithoutThrowing()
    {
        Assert.True(DnsName.TryValidate("example.com", out string? ok));
        Assert.Null(ok);

        Assert.False(DnsName.TryValidate("a..b", out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public void ToReverseLookupName_IPv4()
    {
        Assert.Equal("8.8.4.4.in-addr.arpa", DnsName.ToReverseLookupName(IPAddress.Parse("4.4.8.8")));
        Assert.Equal("20.10.10.10.in-addr.arpa", DnsName.ToReverseLookupName(IPAddress.Parse("10.10.10.20")));
    }

    [Fact]
    public void ToReverseLookupName_IPv6()
    {
        string reverse = DnsName.ToReverseLookupName(IPAddress.Parse("2001:4860:4860::8888"));

        Assert.EndsWith("ip6.arpa", reverse, StringComparison.Ordinal);
        Assert.StartsWith("8.8.8.8.0.0.0.0", reverse, StringComparison.Ordinal);
        // 32 nibbles, each followed by a dot, plus "ip6.arpa"
        Assert.Equal((32 * 2) + "ip6.arpa".Length, reverse.Length);
    }

    [Fact]
    public void ToReverseLookupName_IPv6_HasThirtyTwoNibbles()
    {
        string reverse = DnsName.ToReverseLookupName(IPAddress.Parse("::1"));
        string[] parts = reverse.Split('.');

        Assert.Equal(34, parts.Length); // 32 nibbles + "ip6" + "arpa"
        Assert.Equal("1", parts[0]);
        Assert.Equal("arpa", parts[^1]);
    }

    [Fact]
    public void Read_DecodesUncompressedName()
    {
        byte[] encoded = DnsName.Encode("mail.example.org");
        int offset = 0;

        Assert.Equal("mail.example.org.", DnsName.Read(encoded, ref offset));
        Assert.Equal(encoded.Length, offset);
    }

    [Fact]
    public void Read_EscapesNonPrintableBytes()
    {
        byte[] raw = { 2, 0x01, (byte)'a', 0 };
        int offset = 0;

        Assert.Equal("\\001a.", DnsName.Read(raw, ref offset));
    }

    [Fact]
    public void Read_StopsAtBufferEnd()
    {
        byte[] raw = { 5, (byte)'a' }; // claims a 5 byte label but only supplies 1
        int offset = 0;

        Assert.Throws<DnsProtocolException>(() =>
        {
            int local = offset;
            DnsName.Read(raw, ref local);
        });
    }
}
