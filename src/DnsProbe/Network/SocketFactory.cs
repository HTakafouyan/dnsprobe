using System.Net;
using System.Net.Sockets;

namespace DnsProbe.Network;

/// <summary>Describes exactly how a socket should be pinned to the local network stack.</summary>
public sealed class SocketBinding
{
    public SocketBinding(AddressFamily family, ProtocolType protocol, IPAddress? sourceAddress, int? interfaceIndex, bool useUnicastInterfaceOption = true)
    {
        Family = family;
        Protocol = protocol;
        SourceAddress = sourceAddress;
        InterfaceIndex = interfaceIndex;
        UseUnicastInterfaceOption = useUnicastInterfaceOption;
    }

    public AddressFamily Family { get; }

    public ProtocolType Protocol { get; }

    /// <summary>Bound with Socket.Bind. Null means "let the routing table choose".</summary>
    public IPAddress? SourceAddress { get; }

    /// <summary>Applied with IP_UNICAST_IF / IPV6_UNICAST_IF. Null means "do not pin".</summary>
    public int? InterfaceIndex { get; }

    /// <summary>Set to false by --no-unicast-if to fall back to plain source binding.</summary>
    public bool UseUnicastInterfaceOption { get; }
}

public interface ISocketFactory
{
    Socket Create(SocketBinding binding, out IReadOnlyList<string> notes);
}

/// <summary>
/// Creates the DNS socket and applies both mechanisms that matter on Windows:
/// <list type="number">
/// <item><b>Source address binding</b> via <see cref="Socket.Bind"/>. This fixes the IP that
/// appears in the source field of the outgoing packet, and nothing else.</item>
/// <item><b>Interface pinning</b> via the <c>IP_UNICAST_IF</c> (IPv4) / <c>IPV6_UNICAST_IF</c> (IPv6)
/// socket options. These make the TCP/IP stack perform the route lookup as if it were constrained
/// to the given interface, which is the only supported way to force outbound traffic onto a
/// specific adapter from user mode.</item>
/// </list>
/// Both are applied because neither alone is sufficient: binding controls the source field but not
/// the egress interface, while the unicast-if option controls the egress interface but leaves the
/// source address to the stack.
/// </summary>
public sealed class SocketFactory : ISocketFactory
{
    // Winsock option values. Both happen to be 31, but at different levels.
    private const int IP_UNICAST_IF = 31;   // level IPPROTO_IP   (0)
    private const int IPV6_UNICAST_IF = 31; // level IPPROTO_IPV6 (41)

    public Socket Create(SocketBinding binding, out IReadOnlyList<string> notes)
    {
        var messages = new List<string>();
        notes = messages;

        SocketType socketType = binding.Protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram;
        var socket = new Socket(binding.Family, socketType, binding.Protocol);

        try
        {
            if (binding.Family == AddressFamily.InterNetworkV6)
            {
                // Never let a v6 socket silently carry v4 traffic: address families must not be mixed.
                socket.DualMode = false;
            }

            if (binding.InterfaceIndex is int index && index > 0 && binding.UseUnicastInterfaceOption)
            {
                ApplyUnicastInterface(socket, binding.Family, index, messages);
            }
            else if (binding.InterfaceIndex is not null && !binding.UseUnicastInterfaceOption)
            {
                messages.Add("--no-unicast-if was specified: only Socket.Bind() is used, so the egress interface "
                             + "is chosen by the Windows routing table.");
            }

            IPAddress bindAddress = binding.SourceAddress
                                    ?? (binding.Family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);

            socket.Bind(new IPEndPoint(bindAddress, 0));

            if (binding.SourceAddress is null)
            {
                messages.Add("No source address was pinned; the socket is bound to the wildcard address and the "
                             + "routing table selects the source IP.");
            }

            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Applies IP_UNICAST_IF / IPV6_UNICAST_IF.
    /// </summary>
    /// <remarks>
    /// Byte order is the classic trap here: the IPv4 option takes the interface index in
    /// <b>network</b> byte order, while the IPv6 option takes it in <b>host</b> byte order.
    /// Getting this wrong does not fail - it silently pins the socket to a nonsense interface,
    /// which is exactly the kind of bug this tool exists to expose.
    /// </remarks>
    private static void ApplyUnicastInterface(Socket socket, AddressFamily family, int interfaceIndex, List<string> notes)
    {
        try
        {
            if (family == AddressFamily.InterNetwork)
            {
                int networkOrderIndex = IPAddress.HostToNetworkOrder(interfaceIndex);
                socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IP_UNICAST_IF, networkOrderIndex);
                notes.Add($"IP_UNICAST_IF was set to interface index {interfaceIndex} (network byte order).");
            }
            else
            {
                socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_UNICAST_IF, interfaceIndex);
                notes.Add($"IPV6_UNICAST_IF was set to interface index {interfaceIndex} (host byte order).");
            }
        }
        catch (SocketException ex)
        {
            throw new SocketConfigurationException(
                $"Could not pin the socket to interface index {interfaceIndex} "
                + $"({(family == AddressFamily.InterNetwork ? "IP_UNICAST_IF" : "IPV6_UNICAST_IF")}): {ex.SocketErrorCode}. "
                + "Pass --no-unicast-if to fall back to plain source binding.",
                ex);
        }
    }
}

/// <summary>Raised when the socket cannot be configured the way the user asked for.</summary>
public sealed class SocketConfigurationException : Exception
{
    public SocketConfigurationException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}
