using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsProbe.Dns;

namespace DnsProbe.Cli;

/// <summary>Outcome of parsing argv.</summary>
public sealed class ParseResult
{
    private ParseResult(ProbeOptions? options, string? error)
    {
        Options = options;
        Error = error;
    }

    public ProbeOptions? Options { get; }

    public string? Error { get; }

    public bool Success => Options is not null;

    public static ParseResult Ok(ProbeOptions options) => new(options, null);

    public static ParseResult Fail(string error) => new(null, error);
}

/// <summary>
/// Hand written argument parser. No third party dependency, and it validates the combinations
/// that actually matter for this tool rather than accepting nonsense and failing later.
/// </summary>
public static class CommandLineParser
{
    public static ParseResult Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var options = new ProbeOptions();

        if (args.Length == 0)
        {
            options.Command = ProbeCommand.Interactive;
            return ParseResult.Ok(options);
        }

        var positional = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            string argument = args[i];

            if (argument.Length == 0)
            {
                continue;
            }

            if (argument[0] != '-')
            {
                positional.Add(argument);
                continue;
            }

            string name = argument;
            string? inlineValue = null;

            int equals = argument.IndexOf('=');
            if (equals > 0)
            {
                name = argument[..equals];
                inlineValue = argument[(equals + 1)..];
            }

            switch (name.ToLowerInvariant())
            {
                case "-h":
                case "-?":
                case "--help":
                    options.Command = ProbeCommand.Help;
                    return ParseResult.Ok(options);

                case "--version":
                    options.Command = ProbeCommand.Version;
                    return ParseResult.Ok(options);

                case "--interfaces":
                case "--list-interfaces":
                    options.Command = ProbeCommand.ListInterfaces;
                    break;

                case "--all":
                case "--show-all":
                    options.ShowAllInterfaces = true;
                    break;

                case "-i":
                case "--interface":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    options.InterfaceName = value;
                    break;
                }

                case "--interface-index":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index) || index <= 0)
                    {
                        return ParseResult.Fail($"--interface-index expects a positive integer, got \"{value}\".");
                    }

                    options.InterfaceIndex = index;
                    break;
                }

                case "--source-ip":
                case "--source":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!IPAddress.TryParse(value, out IPAddress? source))
                    {
                        return ParseResult.Fail($"--source-ip expects a valid IP address, got \"{value}\".");
                    }

                    options.SourceIp = source;
                    break;
                }

                case "-s":
                case "--server":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!TryParseServer(value!, out IPAddress? server, out int port, out string? serverError))
                    {
                        return ParseResult.Fail(serverError!);
                    }

                    options.ServerAddress = server;
                    options.ServerPort = port;
                    break;
                }

                case "--port":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port)
                        || port is < 1 or > 65535)
                    {
                        return ParseResult.Fail($"--port expects a value between 1 and 65535, got \"{value}\".");
                    }

                    options.ServerPort = port;
                    break;
                }

                case "--system-dns":
                    options.UseSystemDns = true;
                    break;

                case "-t":
                case "--type":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!TryParseRecordType(value!, out DnsRecordType type))
                    {
                        return ParseResult.Fail(
                            $"Unknown record type \"{value}\". Supported: A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV, ANY, or a numeric type.");
                    }

                    options.RecordType = type;
                    options.RecordTypeExplicit = true;
                    break;
                }

                case "--protocol":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    switch (value!.ToLowerInvariant())
                    {
                        case "udp":
                            options.Transport = DnsTransport.Udp;
                            break;
                        case "tcp":
                            options.Transport = DnsTransport.Tcp;
                            break;
                        default:
                            return ParseResult.Fail($"--protocol expects \"udp\" or \"tcp\", got \"{value}\".");
                    }

                    break;
                }

                case "--tcp":
                    options.Transport = DnsTransport.Tcp;
                    break;

                case "--udp":
                    options.Transport = DnsTransport.Udp;
                    break;

                case "--tcp-fallback":
                    options.TcpFallback = true;
                    break;

                case "--timeout":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int timeout)
                        || timeout is < 1 or > 600000)
                    {
                        return ParseResult.Fail($"--timeout expects milliseconds between 1 and 600000, got \"{value}\".");
                    }

                    options.TimeoutMilliseconds = timeout;
                    break;
                }

                case "--retries":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int retries)
                        || retries is < 0 or > 10)
                    {
                        return ParseResult.Fail($"--retries expects a value between 0 and 10, got \"{value}\".");
                    }

                    options.Retries = retries;
                    break;
                }

                case "-c":
                case "--count":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int count)
                        || count is < 1 or > 10000)
                    {
                        return ParseResult.Fail($"--count expects a value between 1 and 10000, got \"{value}\".");
                    }

                    options.Count = count;
                    break;
                }

                case "--interval":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int interval)
                        || interval is < 0 or > 60000)
                    {
                        return ParseResult.Fail($"--interval expects milliseconds between 0 and 60000, got \"{value}\".");
                    }

                    options.IntervalMilliseconds = interval;
                    break;
                }

                case "-v":
                case "--verbose":
                    options.Verbose = true;
                    break;

                case "--debug":
                    options.Debug = true;
                    options.Verbose = true;
                    break;

                case "--route-check":
                    options.RouteCheck = true;
                    break;

                case "--compare":
                    options.Compare = true;
                    break;

                case "-4":
                case "--ipv4":
                    options.ForcedFamily = AddressFamily.InterNetwork;
                    break;

                case "-6":
                case "--ipv6":
                    options.ForcedFamily = AddressFamily.InterNetworkV6;
                    break;

                case "--allow-down":
                    options.AllowDownInterface = true;
                    break;

                case "--no-unicast-if":
                    options.NoUnicastInterface = true;
                    break;

                case "--no-color":
                case "--no-colour":
                    options.NoColor = true;
                    break;

                case "--json":
                    options.Json = true;
                    break;

                case "--short":
                    options.Short = true;
                    break;

                case "--trace":
                    options.Trace = true;
                    break;

                case "--trace-servers":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int count)
                        || count < 1
                        || count > 13)
                    {
                        return ParseResult.Fail(
                            $"--trace-servers expects a number between 1 and 13, got \"{value}\".");
                    }

                    options.Trace = true;
                    options.TraceServersPerLevel = count;
                    break;
                }

                case "--compare-all":
                    options.Compare = true;
                    options.CompareAll = true;
                    break;

                case "--class":
                {
                    if (!TryTakeValue(args, ref i, inlineValue, name, out string? value, out string? error))
                    {
                        return ParseResult.Fail(error!);
                    }

                    if (!TryParseRecordClass(value!, out DnsRecordClass recordClass))
                    {
                        return ParseResult.Fail(
                            $"Unknown record class \"{value}\". Supported: IN, CS, CH, HS, ANY, "
                            + "or a numeric class.");
                    }

                    options.RecordClass = recordClass;
                    break;
                }

                case "--no-edns":
                    options.UseEdns = false;
                    break;

                case "--dnssec":
                    options.DnssecOk = true;
                    options.UseEdns = true;
                    break;

                case "--nsid":
                    options.RequestNsid = true;
                    options.UseEdns = true;
                    break;

                case "--edns":
                {
                    options.UseEdns = true;

                    // The size is optional: "--edns" alone keeps the default.
                    string? sizeText = inlineValue;

                    if (sizeText is null && i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        sizeText = args[++i];
                    }

                    if (sizeText is not null)
                    {
                        if (!ushort.TryParse(sizeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out ushort size)
                            || size < EdnsOptions.MinimumUdpPayloadSize
                            || size > EdnsOptions.MaximumUdpPayloadSize)
                        {
                            return ParseResult.Fail(
                                $"--edns expects a UDP payload size between {EdnsOptions.MinimumUdpPayloadSize} "
                                + $"and {EdnsOptions.MaximumUdpPayloadSize}, got \"{sizeText}\".");
                        }

                        options.EdnsUdpPayloadSize = size;
                    }

                    break;
                }

                case "--no-recurse":
                    options.NoRecursion = true;
                    break;

                default:
                    // The entry point already appends the "run --help" hint to every parse error,
                    // so repeating it here would print it twice.
                    return ParseResult.Fail($"Unknown option \"{argument}\".");
            }
        }

        if (options.Command == ProbeCommand.ListInterfaces)
        {
            return ParseResult.Ok(options);
        }

        if (positional.Count == 0)
        {
            return ParseResult.Fail("No query name was given. Example: dnsprobe example.com --interface \"Ethernet 2\"");
        }

        if (positional.Count > 1)
        {
            return ParseResult.Fail(
                $"Only one query name is supported, but {positional.Count} were given ({string.Join(", ", positional)}). "
                + "Quote names that contain spaces.");
        }

        options.QueryName = positional[0];
        options.ApplyImplicitPtr();

        string? validationError = Validate(options);
        return validationError is null ? ParseResult.Ok(options) : ParseResult.Fail(validationError);
    }

    /// <summary>Rejects combinations that cannot be satisfied, with an explanation.</summary>
    public static string? Validate(ProbeOptions options)
    {
        if (options.QueryName is not null
            && options.RecordType != DnsRecordType.PTR
            && !DnsName.TryValidate(options.QueryName, out string? nameError))
        {
            return nameError;
        }

        if (options.RecordType == DnsRecordType.PTR
            && !IPAddress.TryParse(options.QueryName, out _)
            && options.QueryName is not null
            && !DnsName.TryValidate(options.QueryName, out string? ptrError))
        {
            return ptrError;
        }

        if (options.Trace && options.Compare)
        {
            return "--trace walks the delegation chain from the root servers, so it cannot be "
                   + "combined with --compare.";
        }

        if (options.Trace && options.UseSystemDns)
        {
            return "--trace starts at the root servers and does not use a configured resolver, so "
                   + "--system-dns has no meaning with it.";
        }

        if (options.Trace && options.Count > 1)
        {
            return "--trace cannot be combined with --count.";
        }

        if (!options.UseEdns && (options.DnssecOk || options.RequestNsid))
        {
            return "--dnssec and --nsid are carried inside the EDNS(0) OPT record, so they cannot be "
                   + "combined with --no-edns.";
        }

        if (options.UseSystemDns && options.ServerAddress is not null)
        {
            return "--system-dns and --server cannot be combined: either the interface's configured servers are used, "
                   + "or the one you named.";
        }

        if (options.Compare && options.InterfaceName is not null)
        {
            return "--compare tests every eligible interface, so it cannot be combined with --interface.";
        }

        if (options.Compare && options.InterfaceIndex is not null)
        {
            return "--compare tests every eligible interface, so it cannot be combined with --interface-index.";
        }

        if (options.Compare && options.SourceIp is not null)
        {
            return "--compare picks the source address of each interface itself, so it cannot be combined with --source-ip.";
        }

        if (options.Compare && options.ServerAddress is null && !options.UseSystemDns)
        {
            return "--compare needs a fixed target: specify --server <ip> so that every interface is tested against "
                   + "the same DNS server.";
        }

        if (options.ForcedFamily is AddressFamily forced
            && options.SourceIp is not null
            && options.SourceIp.AddressFamily != forced)
        {
            return $"--{(forced == AddressFamily.InterNetwork ? "ipv4" : "ipv6")} conflicts with the source IP {options.SourceIp}.";
        }

        if (options.ForcedFamily is AddressFamily forcedServer
            && options.ServerAddress is not null
            && options.ServerAddress.AddressFamily != forcedServer)
        {
            return $"--{(forcedServer == AddressFamily.InterNetwork ? "ipv4" : "ipv6")} conflicts with the DNS server {options.ServerAddress}.";
        }

        if (options.SourceIp is not null
            && options.ServerAddress is not null
            && options.SourceIp.AddressFamily != options.ServerAddress.AddressFamily)
        {
            return $"Address family mismatch: source {options.SourceIp} and server {options.ServerAddress} are not the same family.";
        }

        return null;
    }

    private static bool TryTakeValue(
        string[] args,
        ref int index,
        string? inlineValue,
        string optionName,
        out string? value,
        out string? error)
    {
        if (inlineValue is not null)
        {
            if (inlineValue.Length == 0)
            {
                value = null;
                error = $"{optionName} was given an empty value.";
                return false;
            }

            value = inlineValue;
            error = null;
            return true;
        }

        if (index + 1 >= args.Length)
        {
            value = null;
            error = $"{optionName} requires a value.";
            return false;
        }

        index++;
        value = args[index];
        error = null;
        return true;
    }

    /// <summary>Accepts "10.0.0.53", "10.0.0.53#5353", "[2001:db8::1]:5353" and plain IPv6 literals.</summary>
    public static bool TryParseServer(string text, out IPAddress? address, out int port, out string? error)
    {
        address = null;
        port = 53;
        error = null;

        string value = text.Trim();

        if (value.Length == 0)
        {
            error = "--server requires an IP address.";
            return false;
        }

        int hash = value.LastIndexOf('#');
        if (hash > 0)
        {
            if (!int.TryParse(value[(hash + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out port)
                || port is < 1 or > 65535)
            {
                error = $"\"{value}\" has an invalid port after '#'.";
                return false;
            }

            value = value[..hash];
        }
        else if (value.StartsWith('['))
        {
            int close = value.IndexOf(']');
            if (close < 0)
            {
                error = $"\"{text}\" is missing the closing bracket of the IPv6 literal.";
                return false;
            }

            string remainder = value[(close + 1)..];
            if (remainder.StartsWith(':'))
            {
                if (!int.TryParse(remainder[1..], NumberStyles.Integer, CultureInfo.InvariantCulture, out port)
                    || port is < 1 or > 65535)
                {
                    error = $"\"{text}\" has an invalid port.";
                    return false;
                }
            }
            else if (remainder.Length > 0)
            {
                error = $"\"{text}\" is not a valid server specification.";
                return false;
            }

            value = value[1..close];
        }

        if (!IPAddress.TryParse(value, out address))
        {
            error = $"--server expects an IP address, got \"{text}\". "
                    + "DnsProbe never resolves the DNS server name itself, because that would require a working resolver.";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses a DNS class. CH matters more than it looks: version.bind and id.server are only
    /// meaningful in class CH, and asking for them in class IN returns NXDOMAIN from every server.
    /// </summary>
    public static bool TryParseRecordClass(string text, out DnsRecordClass recordClass)
    {
        if (Enum.TryParse(text, ignoreCase: true, out recordClass) && Enum.IsDefined(recordClass))
        {
            return true;
        }

        if (ushort.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out ushort numeric))
        {
            recordClass = (DnsRecordClass)numeric;
            return true;
        }

        recordClass = DnsRecordClass.IN;
        return false;
    }

    public static bool TryParseRecordType(string text, out DnsRecordType type)
    {
        string value = text.Trim();

        if (Enum.TryParse(value, ignoreCase: true, out DnsRecordType parsed) && Enum.IsDefined(typeof(DnsRecordType), parsed))
        {
            type = parsed;
            return true;
        }

        if (value.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase)
            && ushort.TryParse(value[4..], NumberStyles.Integer, CultureInfo.InvariantCulture, out ushort numeric))
        {
            type = (DnsRecordType)numeric;
            return true;
        }

        if (ushort.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out ushort raw))
        {
            type = (DnsRecordType)raw;
            return true;
        }

        type = DnsRecordType.A;
        return false;
    }
}
