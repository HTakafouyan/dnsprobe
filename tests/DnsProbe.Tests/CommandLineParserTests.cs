using System.Net;
using System.Net.Sockets;
using DnsProbe.Cli;
using DnsProbe.Dns;
using Xunit;

namespace DnsProbe.Tests;

public class CommandLineParserTests
{
    private static ProbeOptions ParseOk(params string[] args)
    {
        ParseResult result = CommandLineParser.Parse(args);
        Assert.True(result.Success, result.Error);
        return result.Options!;
    }

    private static string ParseError(params string[] args)
    {
        ParseResult result = CommandLineParser.Parse(args);
        Assert.False(result.Success);
        return result.Error!;
    }

    [Fact]
    public void NoArgumentsStartsInteractiveMode()
    {
        Assert.Equal(ProbeCommand.Interactive, ParseOk().Command);
    }

    [Fact]
    public void HostnameOnlyDefaultsToARecordOverUdp()
    {
        ProbeOptions options = ParseOk("example.com");

        Assert.Equal(ProbeCommand.Query, options.Command);
        Assert.Equal("example.com", options.QueryName);
        Assert.Equal(DnsRecordType.A, options.RecordType);
        Assert.Equal(DnsTransport.Udp, options.Transport);
        Assert.Equal(2000, options.TimeoutMilliseconds);
        Assert.Equal(53, options.ServerPort);
        Assert.Equal(1, options.Count);
    }

    [Fact]
    public void InterfaceAndServerAreParsed()
    {
        ProbeOptions options = ParseOk("example.com", "--interface", "Ethernet 2", "--server", "10.10.10.53");

        Assert.Equal("Ethernet 2", options.InterfaceName);
        Assert.Equal(IPAddress.Parse("10.10.10.53"), options.ServerAddress);
    }

    [Fact]
    public void EqualsSyntaxIsSupported()
    {
        ProbeOptions options = ParseOk("example.com", "--interface=Ethernet 2", "--type=AAAA");

        Assert.Equal("Ethernet 2", options.InterfaceName);
        Assert.Equal(DnsRecordType.AAAA, options.RecordType);
    }

    [Fact]
    public void ShortOptionsAreSupported()
    {
        ProbeOptions options = ParseOk("example.com", "-i", "Ethernet", "-s", "1.1.1.1", "-t", "MX", "-c", "3", "-v");

        Assert.Equal("Ethernet", options.InterfaceName);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), options.ServerAddress);
        Assert.Equal(DnsRecordType.MX, options.RecordType);
        Assert.Equal(3, options.Count);
        Assert.True(options.Verbose);
    }

    [Fact]
    public void ServerPortCanBeGivenWithHash()
    {
        ProbeOptions options = ParseOk("example.com", "--server", "10.10.10.53#5353");

        Assert.Equal(IPAddress.Parse("10.10.10.53"), options.ServerAddress);
        Assert.Equal(5353, options.ServerPort);
    }

    [Fact]
    public void IPv6ServerLiteralIsSupported()
    {
        ProbeOptions options = ParseOk("example.com", "--server", "2001:4860:4860::8888");

        Assert.Equal(IPAddress.Parse("2001:4860:4860::8888"), options.ServerAddress);
        Assert.Equal(53, options.ServerPort);
    }

    [Fact]
    public void BracketedIPv6ServerWithPortIsSupported()
    {
        ProbeOptions options = ParseOk("example.com", "--server", "[2001:db8::1]:5353");

        Assert.Equal(IPAddress.Parse("2001:db8::1"), options.ServerAddress);
        Assert.Equal(5353, options.ServerPort);
    }

    [Fact]
    public void IpArgumentImpliesPtr()
    {
        ProbeOptions options = ParseOk("8.8.8.8");

        Assert.Equal(DnsRecordType.PTR, options.RecordType);
        Assert.Equal("8.8.8.8.in-addr.arpa", options.ResolveWireName());
    }

    [Fact]
    public void ExplicitTypeOverridesTheImplicitPtr()
    {
        ProbeOptions options = ParseOk("8.8.8.8", "--type", "A");

        Assert.Equal(DnsRecordType.A, options.RecordType);
        Assert.Equal("8.8.8.8", options.ResolveWireName());
    }

    [Fact]
    public void TcpShorthandSetsTransport()
    {
        Assert.Equal(DnsTransport.Tcp, ParseOk("example.com", "--tcp").Transport);
        Assert.Equal(DnsTransport.Tcp, ParseOk("example.com", "--protocol", "tcp").Transport);
        Assert.Equal(DnsTransport.Udp, ParseOk("example.com", "--protocol", "udp").Transport);
    }

    [Fact]
    public void FamilyFlagsAreParsed()
    {
        Assert.Equal(AddressFamily.InterNetwork, ParseOk("example.com", "-4").ForcedFamily);
        Assert.Equal(AddressFamily.InterNetworkV6, ParseOk("example.com", "--ipv6").ForcedFamily);
    }

    [Fact]
    public void DebugImpliesVerbose()
    {
        ProbeOptions options = ParseOk("example.com", "--debug");

        Assert.True(options.Debug);
        Assert.True(options.Verbose);
    }

    [Fact]
    public void InterfacesCommandDoesNotRequireAName()
    {
        ProbeOptions options = ParseOk("--interfaces", "--all");

        Assert.Equal(ProbeCommand.ListInterfaces, options.Command);
        Assert.True(options.ShowAllInterfaces);
    }

    [Fact]
    public void HelpShortCircuitsEverything()
    {
        Assert.Equal(ProbeCommand.Help, ParseOk("--help").Command);
        Assert.Equal(ProbeCommand.Help, ParseOk("example.com", "--help", "--nonsense").Command);
    }

    [Fact]
    public void MissingQueryNameIsAnError()
    {
        Assert.Contains("No query name", ParseError("--interface", "Ethernet 2"), StringComparison.Ordinal);
    }

    [Fact]
    public void TwoPositionalArgumentsAreRejected()
    {
        Assert.Contains("Only one query name", ParseError("example.com", "example.org"), StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownOptionIsRejected()
    {
        Assert.Contains("Unknown option", ParseError("example.com", "--frobnicate"), StringComparison.Ordinal);
    }

    [Fact]
    public void OptionWithoutValueIsRejected()
    {
        Assert.Contains("requires a value", ParseError("example.com", "--server"), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidServerIsRejected()
    {
        Assert.Contains("expects an IP address", ParseError("example.com", "--server", "dns.example.com"), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidSourceIpIsRejected()
    {
        Assert.Contains("valid IP address", ParseError("example.com", "--source-ip", "not-an-ip"), StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidRecordTypeIsRejected()
    {
        Assert.Contains("Unknown record type", ParseError("example.com", "--type", "QQQ"), StringComparison.Ordinal);
    }

    [Fact]
    public void NumericRecordTypeIsAccepted()
    {
        Assert.Equal((DnsRecordType)65, ParseOk("example.com", "--type", "TYPE65").RecordType);
    }

    [Fact]
    public void OutOfRangeNumbersAreRejected()
    {
        Assert.Contains("--timeout", ParseError("example.com", "--timeout", "0"), StringComparison.Ordinal);
        Assert.Contains("--count", ParseError("example.com", "--count", "0"), StringComparison.Ordinal);
        Assert.Contains("--retries", ParseError("example.com", "--retries", "-1"), StringComparison.Ordinal);
        Assert.Contains("--interface-index", ParseError("example.com", "--interface-index", "0"), StringComparison.Ordinal);
        Assert.Contains("--port", ParseError("example.com", "--port", "70000"), StringComparison.Ordinal);
    }

    [Fact]
    public void SystemDnsAndExplicitServerConflict()
    {
        Assert.Contains("cannot be combined", ParseError("example.com", "--system-dns", "--server", "1.1.1.1"), StringComparison.Ordinal);
    }

    [Fact]
    public void CompareCannotBeCombinedWithInterfaceSelection()
    {
        Assert.Contains("--compare", ParseError("example.com", "--compare", "--server", "1.1.1.1", "--interface", "Ethernet"), StringComparison.Ordinal);
        Assert.Contains("--compare", ParseError("example.com", "--compare", "--server", "1.1.1.1", "--source-ip", "10.0.0.1"), StringComparison.Ordinal);
    }

    [Fact]
    public void CompareRequiresAServer()
    {
        Assert.Contains("--compare needs a fixed target", ParseError("example.com", "--compare"), StringComparison.Ordinal);
    }

    [Fact]
    public void FamilyFlagConflictsAreDetected()
    {
        Assert.Contains("conflicts", ParseError("example.com", "-6", "--source-ip", "10.0.0.1"), StringComparison.Ordinal);
        Assert.Contains("conflicts", ParseError("example.com", "-4", "--server", "2001:db8::1"), StringComparison.Ordinal);
    }

    [Fact]
    public void MixedFamiliesBetweenSourceAndServerAreDetected()
    {
        Assert.Contains("Address family mismatch",
            ParseError("example.com", "--source-ip", "10.0.0.1", "--server", "2001:db8::1"),
            StringComparison.Ordinal);
    }

    [Fact]
    public void InvalidHostnameIsRejected()
    {
        Assert.Contains("empty label", ParseError("exam..ple.com"), StringComparison.Ordinal);
    }
}
