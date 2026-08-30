using System.Net;
using System.Net.NetworkInformation;

namespace DnsProbe.Network;

/// <summary>
/// Supplies the list of adapters. The abstraction exists so that selection logic can be
/// unit tested against a synthetic machine with several NICs.
/// </summary>
public interface INetworkInterfaceProvider
{
    IReadOnlyList<InterfaceInfo> GetInterfaces();
}

/// <summary>Reads the real adapter list through System.Net.NetworkInformation.</summary>
public sealed class SystemNetworkInterfaceProvider : INetworkInterfaceProvider
{
    private IReadOnlyList<InterfaceInfo>? _cache;

    public IReadOnlyList<InterfaceInfo> GetInterfaces() => _cache ??= Enumerate();

    /// <summary>Drops the cached snapshot so that the next call re-reads the machine.</summary>
    public void Invalidate() => _cache = null;

    private static IReadOnlyList<InterfaceInfo> Enumerate()
    {
        var result = new List<InterfaceInfo>();

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            IPInterfaceProperties properties;
            try
            {
                properties = nic.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                // A adapter can disappear between enumeration and query; skip it.
                continue;
            }

            var ipv4 = new List<IPAddress>();
            var ipv6 = new List<IPAddress>();

            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                switch (unicast.Address.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        ipv4.Add(unicast.Address);
                        break;
                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        ipv6.Add(unicast.Address);
                        break;
                }
            }

            var gateways = new List<IPAddress>();
            foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
            {
                if (!gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.IPv6Any))
                {
                    gateways.Add(gateway.Address);
                }
            }

            var dnsServers = new List<IPAddress>(properties.DnsAddresses);

            int ipv4Index = 0;
            int ipv6Index = 0;

            try
            {
                ipv4Index = properties.GetIPv4Properties()?.Index ?? 0;
            }
            catch (NetworkInformationException)
            {
                ipv4Index = 0;
            }
            catch (PlatformNotSupportedException)
            {
                ipv4Index = 0;
            }

            try
            {
                ipv6Index = properties.GetIPv6Properties()?.Index ?? 0;
            }
            catch (NetworkInformationException)
            {
                ipv6Index = 0;
            }
            catch (PlatformNotSupportedException)
            {
                ipv6Index = 0;
            }

            long speed;
            try
            {
                speed = nic.Speed;
            }
            catch (PlatformNotSupportedException)
            {
                speed = 0;
            }

            result.Add(new InterfaceInfo(
                nic.Name,
                nic.Description,
                nic.Id,
                ipv4Index,
                ipv6Index,
                nic.OperationalStatus,
                nic.NetworkInterfaceType,
                Classify(nic.Name, nic.Description, nic.NetworkInterfaceType),
                ipv4,
                ipv6,
                gateways,
                dnsServers,
                speed));
        }

        return result;
    }

    /// <summary>
    /// Best-effort classification. Windows does not expose "this is a VPN adapter" directly,
    /// so this uses the adapter type plus well known description keywords.
    /// </summary>
    public static InterfaceCategory Classify(string name, string description, NetworkInterfaceType type)
    {
        string haystack = $"{name} {description}";

        if (type == NetworkInterfaceType.Loopback)
        {
            return InterfaceCategory.Loopback;
        }

        if (ContainsAny(haystack, "hyper-v", "vethernet", "virtual switch"))
        {
            return InterfaceCategory.HyperV;
        }

        if (ContainsAny(haystack, "docker", "wsl", "containers", "podman"))
        {
            return InterfaceCategory.ContainerOrWsl;
        }

        if (ContainsAny(
                haystack,
                "vpn", "wireguard", "wintun", "openvpn", "tap-windows", "anyconnect", "globalprotect",
                "pangp", "fortinet", "forticlient", "fortissl", "zscaler", "tailscale", "zerotier",
                "nordlynx", "sonicwall", "netextender", "softether", "mullvad", "proton vpn",
                "checkpoint", "ipsec", "sstp", "ikev2", "juniper", "pulse secure"))
        {
            return InterfaceCategory.Vpn;
        }

        if (ContainsAny(haystack, "vmware", "virtualbox", "vbox", "parallels", "qemu", "virtio"))
        {
            return InterfaceCategory.VirtualMachine;
        }

        return type switch
        {
            NetworkInterfaceType.Wireless80211 => InterfaceCategory.WiFi,
            NetworkInterfaceType.Ppp => InterfaceCategory.Ppp,
            NetworkInterfaceType.Tunnel => InterfaceCategory.Tunnel,
            NetworkInterfaceType.Ethernet
                or NetworkInterfaceType.GigabitEthernet
                or NetworkInterfaceType.FastEthernetT
                or NetworkInterfaceType.FastEthernetFx
                or NetworkInterfaceType.Ethernet3Megabit => InterfaceCategory.Ethernet,
            _ => InterfaceCategory.Other,
        };
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (string needle in needles)
        {
            if (haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
