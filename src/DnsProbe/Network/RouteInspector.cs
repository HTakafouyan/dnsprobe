using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsProbe.Network;

/// <summary>What the Windows routing table says about a destination.</summary>
public sealed class RouteInfo
{
    public RouteInfo(int interfaceIndex, IPAddress? nextHop, IPAddress? bestSourceAddress, uint metric)
    {
        InterfaceIndex = interfaceIndex;
        NextHop = nextHop;
        BestSourceAddress = bestSourceAddress;
        Metric = metric;
    }

    /// <summary>Index of the interface the packet would leave through.</summary>
    public int InterfaceIndex { get; }

    /// <summary>Gateway address, or the unspecified address when the destination is on-link.</summary>
    public IPAddress? NextHop { get; }

    /// <summary>The source address Windows would choose if the socket were not bound.</summary>
    public IPAddress? BestSourceAddress { get; }

    public uint Metric { get; }

    public bool IsOnLink =>
        NextHop is null || NextHop.Equals(IPAddress.Any) || NextHop.Equals(IPAddress.IPv6Any);

    public string NextHopDisplay => IsOnLink ? "On-link" : NextHop!.ToString();
}

/// <summary>
/// Queries the real Windows routing table. This is what makes it possible to tell the user
/// "you asked to send from Ethernet 2, but the routing table sends this destination out of Ethernet".
/// Nothing here is guessed - if the API fails, the tool says so instead of inventing a route.
/// </summary>
public sealed class RouteInspector
{
    /// <summary>
    /// Looks up the best route for <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">Destination address (normally the DNS server).</param>
    /// <param name="preferredSource">
    /// Optional source address to hand to GetBestRoute2, so the answer reflects the source
    /// the socket will actually be bound to.
    /// </param>
    /// <param name="route">The route, when the call succeeds.</param>
    /// <param name="error">A human readable reason, when it does not.</param>
    public bool TryGetBestRoute(
        IPAddress destination,
        IPAddress? preferredSource,
        out RouteInfo? route,
        out string? error)
    {
        route = null;

        if (!OperatingSystem.IsWindows())
        {
            error = "Routing inspection is only implemented on Windows.";
            return false;
        }

        if (preferredSource is not null && preferredSource.AddressFamily != destination.AddressFamily)
        {
            error = "The source address and the destination address belong to different address families.";
            return false;
        }

        return TryGetBestRouteWindows(destination, preferredSource, out route, out error);
    }

    [SupportedOSPlatform("windows")]
    private static bool TryGetBestRouteWindows(
        IPAddress destination,
        IPAddress? preferredSource,
        out RouteInfo? route,
        out string? error)
    {
        route = null;
        error = null;

        IntPtr destinationPtr = IntPtr.Zero;
        IntPtr sourcePtr = IntPtr.Zero;
        IntPtr routePtr = IntPtr.Zero;
        IntPtr bestSourcePtr = IntPtr.Zero;

        // A generous buffer: the structure is 104 bytes today, 256 leaves room for any future growth.
        const int routeBufferSize = 256;

        try
        {
            byte[] destinationBytes = NativeMethods.CreateSockaddrInet(destination);
            destinationPtr = Marshal.AllocHGlobal(destinationBytes.Length);
            Marshal.Copy(destinationBytes, 0, destinationPtr, destinationBytes.Length);

            if (preferredSource is not null)
            {
                byte[] sourceBytes = NativeMethods.CreateSockaddrInet(preferredSource);
                sourcePtr = Marshal.AllocHGlobal(sourceBytes.Length);
                Marshal.Copy(sourceBytes, 0, sourcePtr, sourceBytes.Length);
            }

            routePtr = Marshal.AllocHGlobal(routeBufferSize);
            bestSourcePtr = Marshal.AllocHGlobal(NativeMethods.SockaddrInetSize);

            ZeroMemory(routePtr, routeBufferSize);
            ZeroMemory(bestSourcePtr, NativeMethods.SockaddrInetSize);

            uint status = NativeMethods.GetBestRoute2(
                IntPtr.Zero,
                0,
                sourcePtr,
                destinationPtr,
                0,
                routePtr,
                bestSourcePtr);

            if (status != NativeMethods.NO_ERROR)
            {
                error = DescribeRouteFailure(status, preferredSource, destination);
                return false;
            }

            byte[] routeBuffer = new byte[NativeMethods.IpForwardRow2Size];
            Marshal.Copy(routePtr, routeBuffer, 0, routeBuffer.Length);

            byte[] bestSourceBuffer = new byte[NativeMethods.SockaddrInetSize];
            Marshal.Copy(bestSourcePtr, bestSourceBuffer, 0, bestSourceBuffer.Length);

            int interfaceIndex = (int)NativeMethods.ReadUInt32(routeBuffer, NativeMethods.OffsetInterfaceIndex);
            IPAddress? nextHop = NativeMethods.ReadSockaddrInet(routeBuffer, NativeMethods.OffsetNextHop);
            IPAddress? bestSource = NativeMethods.ReadSockaddrInet(bestSourceBuffer, 0);
            uint metric = NativeMethods.ReadUInt32(routeBuffer, NativeMethods.OffsetMetric);

            route = new RouteInfo(interfaceIndex, nextHop, bestSource, metric);
            return true;
        }
        catch (DllNotFoundException ex)
        {
            error = $"iphlpapi.dll could not be loaded: {ex.Message}";
            return false;
        }
        catch (EntryPointNotFoundException ex)
        {
            error = $"GetBestRoute2 is not available on this Windows version: {ex.Message}";
            return false;
        }
        catch (NotSupportedException ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            FreeIfNeeded(destinationPtr);
            FreeIfNeeded(sourcePtr);
            FreeIfNeeded(routePtr);
            FreeIfNeeded(bestSourcePtr);
        }
    }

    /// <summary>
    /// Looks up the next hop in the neighbour cache - the ARP table for IPv4, the neighbour
    /// discovery cache for IPv6.
    ///
    /// This answers a question the routing table cannot: the route may exist on paper while the
    /// gateway never answers at layer 2. When that happens every packet is dropped locally and the
    /// query simply times out, which is otherwise indistinguishable from a filtered path.
    /// </summary>
    /// <param name="address">The next hop, or the destination itself when it is on-link.</param>
    /// <param name="interfaceIndex">Interface the neighbour should be reachable on.</param>
    public NeighbourInfo GetNeighbour(IPAddress address, int interfaceIndex)
    {
        if (!OperatingSystem.IsWindows())
        {
            return NeighbourInfo.Unavailable("the neighbour cache is only readable on Windows.");
        }

        IntPtr row = Marshal.AllocHGlobal(NativeMethods.IpNetRow2Size);

        try
        {
            ZeroMemory(row, NativeMethods.IpNetRow2Size);

            byte[] sockaddr = NativeMethods.CreateSockaddrInet(address);
            Marshal.Copy(sockaddr, 0, row + NativeMethods.OffsetNeighbourAddress, sockaddr.Length);
            Marshal.WriteInt32(row, NativeMethods.OffsetNeighbourInterfaceIndex, interfaceIndex);

            uint status = NativeMethods.GetIpNetEntry2(row);

            if (status == NativeMethods.ERROR_NOT_FOUND)
            {
                return NeighbourInfo.Missing(address);
            }

            if (status != NativeMethods.NO_ERROR)
            {
                return NeighbourInfo.Unavailable(
                    $"GetIpNetEntry2 failed with Win32 error {status} "
                    + $"({new System.ComponentModel.Win32Exception((int)status).Message}).");
            }

            byte[] buffer = new byte[NativeMethods.IpNetRow2Size];
            Marshal.Copy(row, buffer, 0, buffer.Length);

            uint state = NativeMethods.ReadUInt32(buffer, NativeMethods.OffsetNeighbourState);
            uint macLength = NativeMethods.ReadUInt32(buffer, NativeMethods.OffsetNeighbourPhysicalAddressLength);

            string? mac = null;

            if (macLength is > 0 and <= 32)
            {
                var parts = new string[macLength];

                for (int i = 0; i < macLength; i++)
                {
                    parts[i] = buffer[NativeMethods.OffsetNeighbourPhysicalAddress + i].ToString("X2");
                }

                mac = string.Join('-', parts);
            }

            return NeighbourInfo.Found(address, (NeighbourState)state, mac);
        }
        catch (DllNotFoundException)
        {
            return NeighbourInfo.Unavailable("iphlpapi.dll is not available.");
        }
        catch (EntryPointNotFoundException)
        {
            return NeighbourInfo.Unavailable("GetIpNetEntry2 is not available on this Windows version.");
        }
        finally
        {
            Marshal.FreeHGlobal(row);
        }
    }

    /// <summary>
    /// Secondary check: which interface index would Windows choose for this destination?
    /// Used to cross-check the GetBestRoute2 answer.
    /// </summary>
    public bool TryGetBestInterfaceIndex(IPAddress destination, out int interfaceIndex, out string? error)
    {
        interfaceIndex = 0;

        if (!OperatingSystem.IsWindows())
        {
            error = "Routing inspection is only implemented on Windows.";
            return false;
        }

        IntPtr destinationPtr = IntPtr.Zero;

        try
        {
            byte[] destinationBytes = NativeMethods.CreateSockaddrInet(destination);
            destinationPtr = Marshal.AllocHGlobal(destinationBytes.Length);
            Marshal.Copy(destinationBytes, 0, destinationPtr, destinationBytes.Length);

            uint status = NativeMethods.GetBestInterfaceEx(destinationPtr, out uint index);
            if (status != NativeMethods.NO_ERROR)
            {
                error = $"GetBestInterfaceEx failed with Win32 error {status}.";
                return false;
            }

            interfaceIndex = (int)index;
            error = null;
            return true;
        }
        catch (DllNotFoundException ex)
        {
            error = $"iphlpapi.dll could not be loaded: {ex.Message}";
            return false;
        }
        catch (EntryPointNotFoundException ex)
        {
            error = $"GetBestInterfaceEx is not available: {ex.Message}";
            return false;
        }
        catch (NotSupportedException ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            FreeIfNeeded(destinationPtr);
        }
    }

    /// <summary>
    /// Compares what the user asked for with what the routing table would do and returns
    /// any inconsistency as a warning. An empty list means "routing agrees with your selection".
    /// </summary>
    public IReadOnlyList<string> Analyse(
        InterfaceInfo? selectedInterface,
        int? selectedIndex,
        IPAddress? selectedSource,
        IPAddress destination,
        RouteInfo? route)
    {
        var warnings = new List<string>();

        if (route is null)
        {
            return warnings;
        }

        if (selectedIndex is int index && index != route.InterfaceIndex)
        {
            warnings.Add(
                $"The routing table would send traffic for {destination} out of interface index {route.InterfaceIndex}, "
                + $"but you selected index {index}"
                + (selectedInterface is null ? string.Empty : $" (\"{selectedInterface.Name}\")")
                + ". The IP_UNICAST_IF/IPV6_UNICAST_IF socket option overrides this, so the packet should still "
                + "leave through your interface - verify with Wireshark, and expect no reply if that path cannot "
                + "reach the server.");
        }

        if (selectedSource is not null
            && route.BestSourceAddress is not null
            && !route.BestSourceAddress.Equals(selectedSource))
        {
            warnings.Add(
                $"Without an explicit binding Windows would have used source {route.BestSourceAddress} for {destination}; "
                + $"the socket is bound to {selectedSource} instead.");
        }

        if (selectedInterface is not null
            && !route.IsOnLink
            && route.NextHop is not null
            && selectedInterface.Gateways.Count > 0)
        {
            bool matches = false;
            foreach (IPAddress gateway in selectedInterface.Gateways)
            {
                if (gateway.Equals(route.NextHop))
                {
                    matches = true;
                    break;
                }
            }

            if (!matches && route.InterfaceIndex != (selectedIndex ?? -1))
            {
                warnings.Add(
                    $"The next hop {route.NextHop} is not a gateway configured on \"{selectedInterface.Name}\".");
            }
        }

        return warnings;
    }

    /// <summary>
    /// Turns a GetBestRoute2 status code into something a human can act on.
    ///
    /// 1231/1232 are not malfunctions: they are the routing table's way of saying "there is no
    /// path", which is a real diagnostic answer and must not be presented as an API failure.
    /// </summary>
    private static string DescribeRouteFailure(uint status, IPAddress? source, IPAddress destination)
    {
        const uint ERROR_NETWORK_UNREACHABLE = 1231;
        const uint ERROR_HOST_UNREACHABLE = 1232;
        const uint ERROR_NOT_FOUND = 1168;

        string from = source is null ? string.Empty : $" from {source}";

        return status switch
        {
            ERROR_NETWORK_UNREACHABLE =>
                $"no route{from} to {destination} - the network is unreachable from this source address.",
            ERROR_HOST_UNREACHABLE =>
                $"no route{from} to {destination} - the host is unreachable.",
            ERROR_NOT_FOUND =>
                $"the routing table has no entry for {destination}.",
            _ =>
                $"GetBestRoute2 failed with Win32 error {status} "
                + $"({new System.ComponentModel.Win32Exception((int)status).Message}).",
        };
    }

    private static void ZeroMemory(IntPtr pointer, int length)
    {
        for (int i = 0; i < length; i++)
        {
            Marshal.WriteByte(pointer, i, 0);
        }
    }

    private static void FreeIfNeeded(IntPtr pointer)
    {
        if (pointer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(pointer);
        }
    }
}
