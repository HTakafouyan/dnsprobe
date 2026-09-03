using System.Net;

namespace DnsProbe.Network;

/// <summary>
/// NL_NEIGHBOR_STATE - how the Windows neighbour cache currently rates an entry.
/// </summary>
public enum NeighbourState
{
    /// <summary>The neighbour is known not to answer.</summary>
    Unreachable = 0,

    /// <summary>Address resolution is in progress and has not completed yet.</summary>
    Incomplete = 1,

    /// <summary>Reachability is being actively probed.</summary>
    Probe = 2,

    /// <summary>The entry is stale and a probe is about to be sent.</summary>
    Delay = 3,

    /// <summary>The entry exists but has not been confirmed recently.</summary>
    Stale = 4,

    /// <summary>The neighbour answered recently. This is the healthy state.</summary>
    Reachable = 5,

    /// <summary>A static entry that never expires.</summary>
    Permanent = 6,
}

/// <summary>
/// The result of a neighbour cache lookup. Three outcomes are possible and they mean very
/// different things, so they are kept distinct rather than collapsed into a nullable.
/// </summary>
public sealed class NeighbourInfo
{
    private NeighbourInfo(bool queried, IPAddress? address, NeighbourState? state, string? macAddress, string? error)
    {
        WasQueried = queried;
        Address = address;
        State = state;
        MacAddress = macAddress;
        Error = error;
    }

    /// <summary>False when the lookup could not be performed at all.</summary>
    public bool WasQueried { get; }

    public IPAddress? Address { get; }

    /// <summary>Null when the address is not in the cache.</summary>
    public NeighbourState? State { get; }

    /// <summary>Link layer address, when one is known.</summary>
    public string? MacAddress { get; }

    /// <summary>Why the lookup could not be performed.</summary>
    public string? Error { get; }

    /// <summary>True when the entry exists and looks usable.</summary>
    public bool IsUsable => State is NeighbourState.Reachable or NeighbourState.Permanent
        or NeighbourState.Stale or NeighbourState.Delay or NeighbourState.Probe;

    /// <summary>True when the entry is present but in a state that will not carry traffic.</summary>
    public bool IsBroken => State is NeighbourState.Unreachable or NeighbourState.Incomplete;

    public static NeighbourInfo Found(IPAddress address, NeighbourState state, string? mac) =>
        new(true, address, state, mac, null);

    public static NeighbourInfo Missing(IPAddress address) => new(true, address, null, null, null);

    public static NeighbourInfo Unavailable(string error) => new(false, null, null, null, error);

    /// <summary>A short label for the diagnostic table.</summary>
    public string Summary()
    {
        if (!WasQueried)
        {
            return "unavailable";
        }

        if (State is null)
        {
            return "not in cache";
        }

        return MacAddress is null
            ? State.ToString()!.ToLowerInvariant()
            : $"{State.ToString()!.ToLowerInvariant()} ({MacAddress})";
    }

    /// <summary>
    /// A sentence explaining what this state means for the query, or null when there is nothing
    /// worth saying.
    /// </summary>
    public string? Explain()
    {
        if (!WasQueried || State is null && Address is null)
        {
            return null;
        }

        if (State is null)
        {
            return $"{Address} is not in the neighbour cache. Windows has not resolved its link layer "
                   + "address, so nothing can be sent to it. Either it is not present on this segment, "
                   + "or it is not answering ARP/neighbour discovery.";
        }

        return State switch
        {
            NeighbourState.Unreachable =>
                $"{Address} is marked unreachable in the neighbour cache: it stopped answering. "
                + "Packets to this next hop are being dropped locally, before they reach the wire.",

            NeighbourState.Incomplete =>
                $"Address resolution for {Address} has not completed. Windows is still asking who "
                + "owns that address and has had no reply yet.",

            _ => null,
        };
    }
}
