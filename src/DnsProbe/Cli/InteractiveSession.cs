using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsProbe.Diagnostics;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Cli;

/// <summary>
/// The zero-argument experience: pick an interface from a numbered list, then a DNS server,
/// then a hostname. Everything the user chooses is turned into normal <see cref="ProbeOptions"/>,
/// so the interactive path and the command line path execute exactly the same code.
/// </summary>
public sealed class InteractiveSession
{
    private readonly INetworkInterfaceProvider _provider;
    private readonly DiagnosticReporter _reporter;
    private readonly TextReader _input;

    public InteractiveSession(INetworkInterfaceProvider provider, DiagnosticReporter reporter, TextReader? input = null)
    {
        _provider = provider;
        _reporter = reporter;
        _input = input ?? Console.In;
    }

    /// <summary>Returns the assembled options, or null when the user aborted.</summary>
    public ProbeOptions? Run()
    {
        var options = new ProbeOptions { Command = ProbeCommand.Query };

        var eligible = new List<InterfaceInfo>();
        foreach (InterfaceInfo nic in _provider.GetInterfaces())
        {
            if (nic.IsUp && !nic.IsLoopback && (nic.Ipv4Addresses.Count > 0 || nic.Ipv6Addresses.Count > 0))
            {
                eligible.Add(nic);
            }
        }

        if (eligible.Count == 0)
        {
            _reporter.WriteError("No active network interface with an IP address was found.");
            return null;
        }

        _reporter.WriteLine("Select Network Interface:");
        _reporter.WriteLine("  [0] (let Windows decide - no interface pinning)");

        for (int i = 0; i < eligible.Count; i++)
        {
            InterfaceInfo nic = eligible[i];
            string addresses = nic.Ipv4Addresses.Count > 0
                ? string.Join(", ", nic.Ipv4Addresses)
                : string.Join(", ", nic.Ipv6Addresses);

            _reporter.WriteLine($"  [{i + 1}] {nic.Name}  {addresses}  ({nic.CategoryLabel})");
        }

        InterfaceInfo? selected = null;
        while (true)
        {
            string? answer = Prompt("Selection: ");
            if (answer is null)
            {
                return null;
            }

            if (answer.Length == 0)
            {
                continue;
            }

            if (!int.TryParse(answer, NumberStyles.Integer, CultureInfo.InvariantCulture, out int choice)
                || choice < 0
                || choice > eligible.Count)
            {
                _reporter.WriteLine($"Please enter a number between 0 and {eligible.Count}.");
                continue;
            }

            if (choice > 0)
            {
                selected = eligible[choice - 1];
                options.InterfaceName = selected.Name;
            }

            break;
        }

        // DNS server -----------------------------------------------------------------
        string? defaultServer = null;
        if (selected is not null && selected.DnsServers.Count > 0)
        {
            defaultServer = selected.DnsServers[0].ToString();
        }

        while (true)
        {
            string prompt = defaultServer is null
                ? "Enter DNS Server: "
                : $"Enter DNS Server [{defaultServer}]: ";

            string? answer = Prompt(prompt);
            if (answer is null)
            {
                return null;
            }

            if (answer.Length == 0)
            {
                if (defaultServer is null)
                {
                    _reporter.WriteLine("A DNS server IP address is required.");
                    continue;
                }

                answer = defaultServer;
            }

            if (!CommandLineParser.TryParseServer(answer, out IPAddress? address, out int port, out string? error))
            {
                _reporter.WriteLine(error!);
                continue;
            }

            options.ServerAddress = address;
            options.ServerPort = port;
            break;
        }

        // Record type ----------------------------------------------------------------
        while (true)
        {
            string? answer = Prompt("Record type [A]: ");
            if (answer is null)
            {
                return null;
            }

            if (answer.Length == 0)
            {
                break;
            }

            if (!CommandLineParser.TryParseRecordType(answer, out DnsRecordType type))
            {
                _reporter.WriteLine("Unknown record type. Try A, AAAA, CNAME, MX, NS, TXT, PTR or SOA.");
                continue;
            }

            options.RecordType = type;
            options.RecordTypeExplicit = true;
            break;
        }

        // Hostname -------------------------------------------------------------------
        while (true)
        {
            string? answer = Prompt("Enter hostname: ");
            if (answer is null)
            {
                return null;
            }

            if (answer.Length == 0)
            {
                continue;
            }

            options.QueryName = answer;
            options.ApplyImplicitPtr();

            string? error = CommandLineParser.Validate(options);
            if (error is not null)
            {
                _reporter.WriteLine(error);
                options.QueryName = null;
                continue;
            }

            break;
        }

        if (options.ServerAddress is not null
            && options.ServerAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            options.ForcedFamily = AddressFamily.InterNetworkV6;
        }

        options.Verbose = true;
        _reporter.WriteLine();
        return options;
    }

    private string? Prompt(string text)
    {
        Console.Out.Write(text);
        Console.Out.Flush();
        return _input.ReadLine()?.Trim();
    }
}
