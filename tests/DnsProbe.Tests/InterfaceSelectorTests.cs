using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DnsProbe.Network;
using Xunit;

namespace DnsProbe.Tests;

/// <summary>A synthetic multi-NIC machine.</summary>
internal sealed class FakeInterfaceProvider : INetworkInterfaceProvider
{
    private readonly List<InterfaceInfo> _interfaces;

    public FakeInterfaceProvider(params InterfaceInfo[] interfaces) => _interfaces = new List<InterfaceInfo>(interfaces);

    public IReadOnlyList<InterfaceInfo> GetInterfaces() => _interfaces;

    public static InterfaceInfo Nic(
        string name,
        string description,
        int index,
        string? ipv4,
        string? ipv6 = null,
        OperationalStatus status = OperationalStatus.Up,
        NetworkInterfaceType type = NetworkInterfaceType.Ethernet,
        string? gateway = null,
        params string[] dnsServers)
    {
        var v4 = new List<IPAddress>();
        var v6 = new List<IPAddress>();

        if (ipv4 is not null)
        {
            v4.Add(IPAddress.Parse(ipv4));
        }

        if (ipv6 is not null)
        {
            v6.Add(IPAddress.Parse(ipv6));
        }

        var gateways = new List<IPAddress>();
        if (gateway is not null)
        {
            gateways.Add(IPAddress.Parse(gateway));
        }

        var dns = new List<IPAddress>();
        foreach (string server in dnsServers)
        {
            dns.Add(IPAddress.Parse(server));
        }

        return new InterfaceInfo(
            name,
            description,
            $"{{{name}}}",
            ipv4 is null ? 0 : index,
            ipv6 is null ? 0 : index,
            status,
            type,
            SystemNetworkInterfaceProvider.Classify(name, description, type),
            v4,
            v6,
            gateways,
            dns);
    }
}

public class InterfaceSelectorTests
{
    private static InterfaceSelector BuildSelector() => new(new FakeInterfaceProvider(
        FakeInterfaceProvider.Nic("Ethernet", "Intel(R) Ethernet Controller", 12, "192.168.1.20",
            "fe80::1", gateway: "192.168.1.1", dnsServers: new[] { "192.168.1.1" }),
        FakeInterfaceProvider.Nic("Ethernet 2", "Intel(R) Ethernet Controller #2", 15, "10.10.10.20",
            "2001:db8::20", gateway: "10.10.10.1", dnsServers: new[] { "10.10.10.53" }),
        FakeInterfaceProvider.Nic("Wi-Fi", "Wireless-AC 9560", 18, null, null,
            OperationalStatus.Down, NetworkInterfaceType.Wireless80211),
        FakeInterfaceProvider.Nic("VPN", "WireGuard Tunnel", 21, "10.20.30.10",
            type: NetworkInterfaceType.Tunnel),
        FakeInterfaceProvider.Nic("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", 30, "172.20.0.1")));

    [Fact]
    public void SelectsInterfaceByExactName()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 2",
        });

        Assert.True(result.Success);
        Assert.Equal("Ethernet 2", result.Interface!.Name);
        Assert.Equal(IPAddress.Parse("10.10.10.20"), result.SourceAddress);
        Assert.Equal(15, result.InterfaceIndex);
        Assert.Equal(AddressFamily.InterNetwork, result.Family);
    }

    [Fact]
    public void ExactNameWinsOverPartialMatch()
    {
        // "Ethernet" is also a substring of "Ethernet 2" and of the Hyper-V description.
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet",
        });

        Assert.True(result.Success);
        Assert.Equal("Ethernet", result.Interface!.Name);
    }

    [Fact]
    public void SelectsInterfaceByIndex()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceIndex = 15,
        });

        Assert.True(result.Success);
        Assert.Equal("Ethernet 2", result.Interface!.Name);
    }

    [Fact]
    public void UnknownInterfaceNameFails()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 9",
        });

        Assert.False(result.Success);
        Assert.Contains("was not found", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownIndexFails()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceIndex = 99,
        });

        Assert.False(result.Success);
        Assert.Contains("index 99", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void NameAndIndexMustAgree()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 2",
            InterfaceIndex = 12,
        });

        Assert.False(result.Success);
        Assert.Contains("does not have index 12", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void SourceIpMustBelongToSelectedInterface()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 2",
            SourceAddress = IPAddress.Parse("192.168.1.20"),
        });

        Assert.False(result.Success);
        Assert.Contains("does not belong to interface \"Ethernet 2\"", result.Error, StringComparison.Ordinal);
        Assert.Contains("Ethernet", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void ConsistentSourceIpAndInterfaceAreAccepted()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 2",
            SourceAddress = IPAddress.Parse("10.10.10.20"),
        });

        Assert.True(result.Success);
        Assert.Equal(15, result.InterfaceIndex);
    }

    [Fact]
    public void SourceIpAloneResolvesTheOwningInterface()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            SourceAddress = IPAddress.Parse("10.10.10.20"),
        });

        Assert.True(result.Success);
        Assert.Equal("Ethernet 2", result.Interface!.Name);
    }

    [Fact]
    public void UnknownSourceIpFails()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            SourceAddress = IPAddress.Parse("203.0.113.7"),
        });

        Assert.False(result.Success);
        Assert.Contains("not assigned to any network interface", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void DownInterfaceIsRejectedByDefault()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Wi-Fi",
        });

        Assert.False(result.Success);
        Assert.Contains("down", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InterfaceWithoutIPv4CannotBeUsedForIPv4()
    {
        var selector = new InterfaceSelector(new FakeInterfaceProvider(
            FakeInterfaceProvider.Nic("IPv6 Only", "Test adapter", 40, null, "2001:db8::1")));

        InterfaceSelectionResult result = selector.Select(new InterfaceSelectionRequest
        {
            InterfaceName = "IPv6 Only",
            ForcedFamily = AddressFamily.InterNetwork,
        });

        Assert.False(result.Success);
        Assert.Contains("no IPv4 address", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void IPv6IsSelectedWhenTheServerIsIPv6()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            InterfaceName = "Ethernet 2",
            ServerAddress = IPAddress.Parse("2001:4860:4860::8888"),
        });

        Assert.True(result.Success);
        Assert.Equal(AddressFamily.InterNetworkV6, result.Family);
        Assert.Equal(IPAddress.Parse("2001:db8::20"), result.SourceAddress);
    }

    [Fact]
    public void MixingFamiliesIsRejected()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest
        {
            SourceAddress = IPAddress.Parse("10.10.10.20"),
            ServerAddress = IPAddress.Parse("2001:4860:4860::8888"),
        });

        Assert.False(result.Success);
        Assert.Contains("Address family mismatch", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void NoSelectionLeavesTheChoiceToTheRoutingTable()
    {
        InterfaceSelectionResult result = BuildSelector().Select(new InterfaceSelectionRequest());

        Assert.True(result.Success);
        Assert.Null(result.Interface);
        Assert.Null(result.SourceAddress);
        Assert.Null(result.InterfaceIndex);
    }

    [Fact]
    public void ClassificationRecognisesVirtualAdapters()
    {
        IReadOnlyList<InterfaceInfo> interfaces = new FakeInterfaceProvider(
            FakeInterfaceProvider.Nic("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", 30, "172.20.0.1"),
            FakeInterfaceProvider.Nic("VPN", "WireGuard Tunnel", 21, "10.20.30.10", type: NetworkInterfaceType.Tunnel),
            FakeInterfaceProvider.Nic("Loopback", "Software Loopback Interface 1", 1, "127.0.0.1",
                type: NetworkInterfaceType.Loopback)).GetInterfaces();

        Assert.Equal(InterfaceCategory.HyperV, interfaces[0].Category);
        Assert.Equal(InterfaceCategory.Vpn, interfaces[1].Category);
        Assert.Equal(InterfaceCategory.Loopback, interfaces[2].Category);
    }
}
