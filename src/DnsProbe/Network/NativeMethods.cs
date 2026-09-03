using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsProbe.Network;

/// <summary>
/// Minimal P/Invoke surface for the Windows routing APIs used by <see cref="RouteInspector"/>.
/// </summary>
/// <remarks>
/// The native structures (SOCKADDR_INET, MIB_IPFORWARD_ROW2) are handled as raw byte buffers with
/// explicit field offsets instead of marshalled structs. That avoids every classic union/packing
/// mistake and keeps the code free of <c>unsafe</c>.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class NativeMethods
{
    internal const uint NO_ERROR = 0;

    internal const ushort AF_INET = 2;
    internal const ushort AF_INET6 = 23;

    /// <summary>sizeof(SOCKADDR_INET) - the union is as large as sockaddr_in6.</summary>
    internal const int SockaddrInetSize = 28;

    /// <summary>
    /// sizeof(MIB_IPFORWARD_ROW2) on both x86 and x64 (NET_LUID forces 8 byte alignment on both).
    /// A larger buffer is allocated at the call site anyway, so a future growth of the structure
    /// cannot overflow anything.
    /// </summary>
    internal const int IpForwardRow2Size = 104;

    // Field offsets inside MIB_IPFORWARD_ROW2.
    internal const int OffsetInterfaceLuid = 0;        // NET_LUID   (8 bytes)
    internal const int OffsetInterfaceIndex = 8;       // NET_IFINDEX (ULONG)
    internal const int OffsetDestinationPrefix = 12;   // IP_ADDRESS_PREFIX (SOCKADDR_INET + UINT8, padded to 32)
    internal const int OffsetNextHop = 44;             // SOCKADDR_INET
    internal const int OffsetMetric = 84;              // ULONG

    /// <summary>
    /// Retrieves the best route (and the source address Windows would pick) for a destination.
    /// </summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    internal static extern uint GetBestRoute2(
        IntPtr interfaceLuid,
        uint interfaceIndex,
        IntPtr sourceAddress,
        IntPtr destinationAddress,
        uint addressSortOptions,
        IntPtr bestRoute,
        IntPtr bestSourceAddress);

    /// <summary>Retrieves the interface index Windows would use to reach a destination.</summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    internal static extern uint GetBestInterfaceEx(IntPtr destinationAddress, out uint bestIfIndex);

    // ------------------------------------------------------------------ neighbour (ARP/ND) table

    /// <summary>
    /// sizeof(MIB_IPNET_ROW2). Field offsets below are for the x64 layout:
    ///   SOCKADDR_INET Address            at   0 (28 bytes)
    ///   NET_IFINDEX   InterfaceIndex     at  28 (ULONG)
    ///   NET_LUID      InterfaceLuid      at  32 (ULONG64, forces 8 byte alignment)
    ///   UCHAR         PhysicalAddress[32] at 40
    ///   ULONG         PhysicalAddressLength at 72
    ///   NL_NEIGHBOR_STATE State          at  76 (enum, ULONG)
    ///   UCHAR         Flags              at  80
    ///   ULONG         ReachabilityTime   at  84
    /// </summary>
    internal const int IpNetRow2Size = 88;

    internal const int OffsetNeighbourAddress = 0;
    internal const int OffsetNeighbourInterfaceIndex = 28;
    internal const int OffsetNeighbourPhysicalAddress = 40;
    internal const int OffsetNeighbourPhysicalAddressLength = 72;
    internal const int OffsetNeighbourState = 76;

    /// <summary>The destination is not in the neighbour table at all.</summary>
    internal const uint ERROR_NOT_FOUND = 1168;

    /// <summary>
    /// Reads one entry from the neighbour cache (the ARP table for IPv4, the neighbour discovery
    /// cache for IPv6). The Address and InterfaceIndex fields must be filled in before the call.
    /// </summary>
    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    internal static extern uint GetIpNetEntry2(IntPtr row);

    /// <summary>Serialises an <see cref="IPAddress"/> into a SOCKADDR_INET buffer.</summary>
    internal static byte[] CreateSockaddrInet(IPAddress address)
    {
        byte[] buffer = new byte[SockaddrInetSize];
        byte[] bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // struct sockaddr_in { USHORT sin_family; USHORT sin_port; IN_ADDR sin_addr; CHAR pad[8]; }
            buffer[0] = unchecked((byte)AF_INET);
            buffer[1] = (byte)(AF_INET >> 8);
            Buffer.BlockCopy(bytes, 0, buffer, 4, 4);
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // struct sockaddr_in6 { USHORT family; USHORT port; ULONG flowinfo; IN6_ADDR addr; ULONG scope_id; }
            buffer[0] = unchecked((byte)AF_INET6);
            buffer[1] = (byte)(AF_INET6 >> 8);
            Buffer.BlockCopy(bytes, 0, buffer, 8, 16);

            uint scopeId = (uint)address.ScopeId;
            buffer[24] = (byte)(scopeId & 0xFF);
            buffer[25] = (byte)((scopeId >> 8) & 0xFF);
            buffer[26] = (byte)((scopeId >> 16) & 0xFF);
            buffer[27] = (byte)((scopeId >> 24) & 0xFF);
        }
        else
        {
            throw new NotSupportedException($"Address family {address.AddressFamily} is not supported.");
        }

        return buffer;
    }

    /// <summary>Reads an <see cref="IPAddress"/> back out of a SOCKADDR_INET buffer.</summary>
    internal static IPAddress? ReadSockaddrInet(byte[] buffer, int offset)
    {
        if (buffer.Length - offset < SockaddrInetSize)
        {
            return null;
        }

        ushort family = (ushort)(buffer[offset] | (buffer[offset + 1] << 8));

        switch (family)
        {
            case AF_INET:
            {
                byte[] raw = new byte[4];
                Buffer.BlockCopy(buffer, offset + 4, raw, 0, 4);
                return new IPAddress(raw);
            }

            case AF_INET6:
            {
                byte[] raw = new byte[16];
                Buffer.BlockCopy(buffer, offset + 8, raw, 0, 16);
                uint scopeId = (uint)(buffer[offset + 24]
                                      | (buffer[offset + 25] << 8)
                                      | (buffer[offset + 26] << 16)
                                      | (buffer[offset + 27] << 24));
                return new IPAddress(raw, scopeId);
            }

            default:
                return null;
        }
    }

    internal static uint ReadUInt32(byte[] buffer, int offset) =>
        (uint)(buffer[offset]
               | (buffer[offset + 1] << 8)
               | (buffer[offset + 2] << 16)
               | (buffer[offset + 3] << 24));

    // ------------------------------------------------------------------ console colour

    private const int STD_OUTPUT_HANDLE = -11;
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    /// <summary>
    /// Turns on ANSI escape sequence handling for stdout. Windows Terminal enables it already;
    /// the legacy console host does not, and would otherwise print the escape codes literally.
    /// </summary>
    /// <returns>True when ANSI colour can be used.</returns>
    internal static bool TryEnableVirtualTerminalProcessing()
    {
        try
        {
            IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return false;
            }

            if (!GetConsoleMode(handle, out uint mode))
            {
                return false;
            }

            if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0)
            {
                return true;
            }

            return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }
}
