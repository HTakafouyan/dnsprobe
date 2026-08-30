using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DnsProbe.Network;

/// <summary>What the user asked for on the command line.</summary>
public sealed class InterfaceSelectionRequest
{
    public string? InterfaceName { get; init; }

    public int? InterfaceIndex { get; init; }

    public IPAddress? SourceAddress { get; init; }

    /// <summary>Set when the user forced --ipv4 or --ipv6.</summary>
    public AddressFamily? ForcedFamily { get; init; }

    /// <summary>Used only to infer the address family when nothing else determines it.</summary>
    public IPAddress? ServerAddress { get; init; }

    /// <summary>When false, a selected adapter that is not Up is rejected.</summary>
    public bool AllowDownInterface { get; init; }
}

/// <summary>The outcome of resolving a selection request against the machine.</summary>
public sealed class InterfaceSelectionResult
{
    private InterfaceSelectionResult(bool success)
    {
        Success = success;
    }

    public bool Success { get; }

    public string? Error { get; private init; }

    /// <summary>Null when the user did not pin an adapter (the OS routing table decides).</summary>
    public InterfaceInfo? Interface { get; private init; }

    /// <summary>Null when the socket should not be bound to a specific source address.</summary>
    public IPAddress? SourceAddress { get; private init; }

    public AddressFamily Family { get; private init; }

    /// <summary>The interface index for <see cref="Family"/>, or null when no adapter was pinned.</summary>
    public int? InterfaceIndex { get; private init; }

    public IReadOnlyList<string> Warnings { get; private init; } = Array.Empty<string>();

    public static InterfaceSelectionResult Failure(string error) =>
        new(false) { Error = error };

    public static InterfaceSelectionResult Ok(
        InterfaceInfo? nic,
        IPAddress? source,
        AddressFamily family,
        int? index,
        IReadOnlyList<string>? warnings = null) =>
        new(true)
        {
            Interface = nic,
            SourceAddress = source,
            Family = family,
            InterfaceIndex = index,
            Warnings = warnings ?? Array.Empty<string>(),
        };
}

/// <summary>
/// Resolves --interface / --interface-index / --source-ip into a concrete
/// (adapter, source address, address family, interface index) tuple, or a clear error.
/// Pure logic: it only touches the supplied <see cref="INetworkInterfaceProvider"/>.
/// </summary>
public sealed class InterfaceSelector
{
    private readonly INetworkInterfaceProvider _provider;

    public InterfaceSelector(INetworkInterfaceProvider provider)
    {
        _provider = provider;
    }

    public InterfaceSelectionResult Select(InterfaceSelectionRequest request)
    {
        IReadOnlyList<InterfaceInfo> interfaces = _provider.GetInterfaces();
        var warnings = new List<string>();

        InterfaceInfo? selected = null;

        // ---- 1. by name -------------------------------------------------------------
        if (!string.IsNullOrWhiteSpace(request.InterfaceName))
        {
            InterfaceSelectionResult? failure = ResolveByName(interfaces, request.InterfaceName!, out selected);
            if (failure is not null)
            {
                return failure;
            }
        }

        // ---- 2. by index ------------------------------------------------------------
        if (request.InterfaceIndex is int wantedIndex)
        {
            InterfaceInfo? byIndex = null;
            foreach (InterfaceInfo nic in interfaces)
            {
                if (nic.Ipv4Index == wantedIndex || nic.Ipv6Index == wantedIndex)
                {
                    byIndex = nic;
                    break;
                }
            }

            if (byIndex is null)
            {
                return InterfaceSelectionResult.Failure(
                    $"No network interface has index {wantedIndex}. Run 'dnsprobe --interfaces' to see the available indexes.");
            }

            if (selected is not null && !ReferenceEquals(selected, byIndex))
            {
                return InterfaceSelectionResult.Failure(
                    $"Interface \"{selected.Name}\" does not have index {wantedIndex}; that index belongs to \"{byIndex.Name}\".");
            }

            selected = byIndex;
        }

        // ---- 3. address family ------------------------------------------------------
        AddressFamily family =
            request.ForcedFamily
            ?? request.SourceAddress?.AddressFamily
            ?? request.ServerAddress?.AddressFamily
            ?? AddressFamily.InterNetwork;

        if (request.ForcedFamily is AddressFamily forced
            && request.SourceAddress is IPAddress src
            && src.AddressFamily != forced)
        {
            return InterfaceSelectionResult.Failure(
                $"--{(forced == AddressFamily.InterNetwork ? "ipv4" : "ipv6")} was requested but the source IP {src} is "
                + $"{(src.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6")}.");
        }

        if (request.ServerAddress is IPAddress server && server.AddressFamily != family)
        {
            return InterfaceSelectionResult.Failure(
                $"Address family mismatch: the DNS server {server} is "
                + $"{(server.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6")} while the query was resolved to "
                + $"{(family == AddressFamily.InterNetwork ? "IPv4" : "IPv6")}. "
                + "DnsProbe never mixes address families.");
        }

        // ---- 4. source address ------------------------------------------------------
        IPAddress? sourceAddress = request.SourceAddress;

        if (sourceAddress is not null)
        {
            InterfaceInfo? owner = null;
            foreach (InterfaceInfo nic in interfaces)
            {
                if (nic.HasAddress(sourceAddress))
                {
                    owner = nic;
                    break;
                }
            }

            if (owner is null)
            {
                return InterfaceSelectionResult.Failure(
                    $"Source IP {sourceAddress} is not assigned to any network interface on this machine. "
                    + "Run 'dnsprobe --interfaces' to see the configured addresses.");
            }

            if (selected is not null && !ReferenceEquals(selected, owner))
            {
                return InterfaceSelectionResult.Failure(
                    $"Source IP {sourceAddress} does not belong to interface \"{selected.Name}\". "
                    + $"It is configured on \"{owner.Name}\".");
            }

            selected = owner;
        }
        else if (selected is not null)
        {
            sourceAddress = selected.PreferredSourceAddress(family);

            if (sourceAddress is null)
            {
                string label = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
                return InterfaceSelectionResult.Failure(
                    $"Interface \"{selected.Name}\" has no {label} address, so a {label} DNS query cannot originate from it.");
            }

            IReadOnlyList<IPAddress> candidates = selected.AddressesFor(family);
            if (candidates.Count > 1)
            {
                warnings.Add(
                    $"Interface \"{selected.Name}\" has {candidates.Count} {(family == AddressFamily.InterNetwork ? "IPv4" : "IPv6")} "
                    + $"addresses; {sourceAddress} was chosen. Use --source-ip to pick a different one.");
            }
        }

        // ---- 5. state checks --------------------------------------------------------
        if (selected is not null)
        {
            if (!selected.IsUp && !request.AllowDownInterface)
            {
                return InterfaceSelectionResult.Failure(
                    $"Interface \"{selected.Name}\" is {DescribeStatus(selected.Status)}. "
                    + "Bring it up, or pass --allow-down to try anyway.");
            }

            if (!selected.IsUp)
            {
                warnings.Add($"Interface \"{selected.Name}\" is {DescribeStatus(selected.Status)}; the query will very likely fail.");
            }
        }

        int? index = null;
        if (selected is not null)
        {
            index = selected.IndexFor(family);
            if (index == 0)
            {
                string label = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
                return InterfaceSelectionResult.Failure(
                    $"Interface \"{selected.Name}\" does not expose an {label} interface index, "
                    + $"which means the {label} stack is not bound to it.");
            }

            if (sourceAddress is not null
                && sourceAddress.AddressFamily == AddressFamily.InterNetworkV6
                && sourceAddress.IsIPv6LinkLocal)
            {
                warnings.Add(
                    $"{sourceAddress} is an IPv6 link-local address. Link-local traffic is only meaningful inside "
                    + $"the scope of interface index {index}.");
            }

            if (sourceAddress is not null && InterfaceInfo.IsIPv4LinkLocal(sourceAddress))
            {
                warnings.Add(
                    $"{sourceAddress} is an APIPA (169.254.0.0/16) address, which usually means DHCP failed on \"{selected.Name}\".");
            }
        }

        return InterfaceSelectionResult.Ok(selected, sourceAddress, family, index, warnings);
    }

    private static InterfaceSelectionResult? ResolveByName(
        IReadOnlyList<InterfaceInfo> interfaces,
        string name,
        out InterfaceInfo? selected)
    {
        selected = null;

        var exact = new List<InterfaceInfo>();
        var partial = new List<InterfaceInfo>();

        foreach (InterfaceInfo nic in interfaces)
        {
            if (string.Equals(nic.Name, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(nic.Description, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(nic.Id, name, StringComparison.OrdinalIgnoreCase))
            {
                exact.Add(nic);
            }
            else if (nic.Name.Contains(name, StringComparison.OrdinalIgnoreCase)
                     || nic.Description.Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                partial.Add(nic);
            }
        }

        if (exact.Count == 1)
        {
            selected = exact[0];
            return null;
        }

        if (exact.Count > 1)
        {
            return InterfaceSelectionResult.Failure(
                $"\"{name}\" matches {exact.Count} interfaces ({Join(exact)}). Use --interface-index instead.");
        }

        if (partial.Count == 1)
        {
            selected = partial[0];
            return null;
        }

        if (partial.Count > 1)
        {
            return InterfaceSelectionResult.Failure(
                $"\"{name}\" is ambiguous - it matches {Join(partial)}. Use the exact name or --interface-index.");
        }

        return InterfaceSelectionResult.Failure(
            $"Network interface \"{name}\" was not found. Run 'dnsprobe --interfaces' to list the available adapters.");
    }

    private static string Join(IReadOnlyList<InterfaceInfo> nics)
    {
        var names = new List<string>(nics.Count);
        foreach (InterfaceInfo nic in nics)
        {
            names.Add(string.Create(CultureInfo.InvariantCulture, $"\"{nic.Name}\" (index {nic.Ipv4Index})"));
        }

        return string.Join(", ", names);
    }

    private static string DescribeStatus(OperationalStatus status) => status switch
    {
        OperationalStatus.Down => "down",
        OperationalStatus.NotPresent => "not present",
        OperationalStatus.LowerLayerDown => "down (the underlying adapter is down)",
        OperationalStatus.Dormant => "dormant",
        OperationalStatus.Testing => "in testing state",
        OperationalStatus.Unknown => "in an unknown state",
        _ => status.ToString().ToLowerInvariant(),
    };
}
