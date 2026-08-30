using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DnsProbe.Network;

/// <summary>Broad classification of an adapter, used for display and for the --compare filter.</summary>
public enum InterfaceCategory
{
    Ethernet,
    WiFi,
    Vpn,
    Tunnel,
    Loopback,
    HyperV,
    ContainerOrWsl,
    VirtualMachine,
    Ppp,
    Other,
}

/// <summary>
/// An immutable snapshot of one network adapter. Deliberately a plain data object so that
/// the selection logic can be unit tested without touching the real machine.
/// </summary>
public sealed class InterfaceInfo
{
    public InterfaceInfo(
        string name,
        string description,
        string id,
        int ipv4Index,
        int ipv6Index,
        OperationalStatus status,
        NetworkInterfaceType type,
        InterfaceCategory category,
        IReadOnlyList<IPAddress> ipv4Addresses,
        IReadOnlyList<IPAddress> ipv6Addresses,
        IReadOnlyList<IPAddress> gateways,
        IReadOnlyList<IPAddress> dnsServers,
        long speed = 0)
    {
        Name = name;
        Description = description;
        Id = id;
        Ipv4Index = ipv4Index;
        Ipv6Index = ipv6Index;
        Status = status;
        Type = type;
        Category = category;
        Ipv4Addresses = ipv4Addresses;
        Ipv6Addresses = ipv6Addresses;
        Gateways = gateways;
        DnsServers = dnsServers;
        Speed = speed;
    }

    /// <summary>Friendly connection name, e.g. "Ethernet 2".</summary>
    public string Name { get; }

    /// <summary>Adapter description, e.g. "Intel(R) Ethernet Controller #2".</summary>
    public string Description { get; }

    /// <summary>The adapter GUID as reported by Windows.</summary>
    public string Id { get; }

    /// <summary>IPv4 interface index, or 0 when the adapter has no IPv4 stack.</summary>
    public int Ipv4Index { get; }

    /// <summary>IPv6 interface index, or 0 when the adapter has no IPv6 stack.</summary>
    public int Ipv6Index { get; }

    public OperationalStatus Status { get; }

    public NetworkInterfaceType Type { get; }

    public InterfaceCategory Category { get; }

    public IReadOnlyList<IPAddress> Ipv4Addresses { get; }

    public IReadOnlyList<IPAddress> Ipv6Addresses { get; }

    public IReadOnlyList<IPAddress> Gateways { get; }

    public IReadOnlyList<IPAddress> DnsServers { get; }

    public long Speed { get; }

    public bool IsUp => Status == OperationalStatus.Up;

    public bool IsLoopback => Type == NetworkInterfaceType.Loopback;

    public bool SupportsIPv4 => Ipv4Index != 0;

    public bool SupportsIPv6 => Ipv6Index != 0;

    public IReadOnlyList<IPAddress> AddressesFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? Ipv6Addresses : Ipv4Addresses;

    public int IndexFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? Ipv6Index : Ipv4Index;

    /// <summary>True when <paramref name="address"/> is configured on this adapter.</summary>
    public bool HasAddress(IPAddress address)
    {
        foreach (IPAddress candidate in Ipv4Addresses)
        {
            if (candidate.Equals(address))
            {
                return true;
            }
        }

        foreach (IPAddress candidate in Ipv6Addresses)
        {
            if (candidate.Equals(address))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Picks the address that should be used as the socket source address for a family.
    /// Global / routable addresses are preferred over link-local ones, because binding a
    /// link-local IPv6 address without a scope id rarely does what the user expects.
    /// </summary>
    public IPAddress? PreferredSourceAddress(AddressFamily family)
    {
        IReadOnlyList<IPAddress> candidates = AddressesFor(family);
        IPAddress? fallback = null;

        foreach (IPAddress address in candidates)
        {
            bool isLinkLocal = address.AddressFamily == AddressFamily.InterNetworkV6
                ? address.IsIPv6LinkLocal
                : IsIPv4LinkLocal(address);

            if (!isLinkLocal)
            {
                return address;
            }

            fallback ??= address;
        }

        return fallback;
    }

    public static bool IsIPv4LinkLocal(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 169 && bytes[1] == 254;
    }

    public string CategoryLabel => Category switch
    {
        InterfaceCategory.Ethernet => "Ethernet (physical)",
        InterfaceCategory.WiFi => "Wi-Fi",
        InterfaceCategory.Vpn => "VPN",
        InterfaceCategory.Tunnel => "Tunnel",
        InterfaceCategory.Loopback => "Loopback",
        InterfaceCategory.HyperV => "Hyper-V virtual switch",
        InterfaceCategory.ContainerOrWsl => "Container / WSL",
        InterfaceCategory.VirtualMachine => "Virtual machine adapter",
        InterfaceCategory.Ppp => "PPP",
        _ => "Other",
    };

    public override string ToString() => $"{Name} (index {Ipv4Index}/{Ipv6Index}, {Status})";
}
