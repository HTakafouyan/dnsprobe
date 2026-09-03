using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsProbe.Diagnostics;
using DnsProbe.Dns;
using DnsProbe.Network;

namespace DnsProbe.Cli;

/// <summary>
/// The zero-argument experience.
///
/// It asks what the user wants to do first, then only the questions that task actually needs.
/// Asking about every option in turn would mean thirty prompts and nobody would reach the end;
/// asking about four of them, as the first version did, hid the features that matter most.
///
/// Everything chosen here is turned into ordinary <see cref="ProbeOptions"/>, so the interactive
/// path and the command line path run exactly the same code. Before running, the equivalent
/// command line is printed - the session is meant to teach itself out of a job.
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

    private enum ProbeTask
    {
        Lookup,
        Compare,
        Reliability,
        RouteCheck,
        ListInterfaces,
        ReverseLookup,
    }

    /// <summary>Returns the assembled options, or null when the user aborted.</summary>
    public ProbeOptions? Run()
    {
        ProbeTask? task = AskTask();

        if (task is null)
        {
            return null;
        }

        ProbeOptions? options = task switch
        {
            ProbeTask.ListInterfaces => BuildListInterfaces(),
            ProbeTask.Compare => BuildCompare(),
            ProbeTask.Reliability => BuildReliability(),
            ProbeTask.RouteCheck => BuildLookup(routeCheck: true),
            ProbeTask.ReverseLookup => BuildReverse(),
            _ => BuildLookup(routeCheck: false),
        };

        if (options is null)
        {
            return null;
        }

        ShowEquivalentCommand(options);
        return options;
    }

    // ---------------------------------------------------------------- the menu

    private ProbeTask? AskTask()
    {
        _reporter.WriteLine("dnsprobe - what would you like to do?");
        _reporter.WriteLine();
        _reporter.WriteLine("  [1] Look up a name");
        _reporter.WriteLine("  [2] Compare every interface against one DNS server");
        _reporter.WriteLine("  [3] Test reliability (repeat a query and show statistics)");
        _reporter.WriteLine("  [4] Look up a name and show the routing path");
        _reporter.WriteLine("  [5] List network interfaces");
        _reporter.WriteLine("  [6] Reverse lookup an IP address");
        _reporter.WriteLine();

        while (true)
        {
            string? answer = Prompt("Choice [1]: ");

            if (answer is null)
            {
                return null;
            }

            if (answer.Length == 0)
            {
                return ProbeTask.Lookup;
            }

            switch (answer)
            {
                case "1": return ProbeTask.Lookup;
                case "2": return ProbeTask.Compare;
                case "3": return ProbeTask.Reliability;
                case "4": return ProbeTask.RouteCheck;
                case "5": return ProbeTask.ListInterfaces;
                case "6": return ProbeTask.ReverseLookup;
                default:
                    _reporter.WriteLine("Please enter a number between 1 and 6.");
                    continue;
            }
        }
    }

    // ---------------------------------------------------------------- task builders

    private ProbeOptions BuildListInterfaces()
    {
        var options = new ProbeOptions { Command = ProbeCommand.ListInterfaces };
        options.ShowAllInterfaces = AskYesNo("Include loopback and inactive adapters?", defaultYes: false);
        return options;
    }

    private ProbeOptions? BuildLookup(bool routeCheck)
    {
        var options = new ProbeOptions { Command = ProbeCommand.Query, Verbose = true, RouteCheck = routeCheck };

        InterfaceInfo? selected = AskInterface(options, out bool aborted);
        if (aborted)
        {
            return null;
        }

        if (!AskServer(options, selected))
        {
            return null;
        }

        if (!AskRecordType(options))
        {
            return null;
        }

        return AskName(options, "Name to look up: ") ? Finish(options) : null;
    }

    private ProbeOptions? BuildReverse()
    {
        var options = new ProbeOptions { Command = ProbeCommand.Query, Verbose = true };

        InterfaceInfo? selected = AskInterface(options, out bool aborted);
        if (aborted)
        {
            return null;
        }

        if (!AskServer(options, selected))
        {
            return null;
        }

        while (true)
        {
            string? answer = Prompt("IP address to look up: ");

            if (answer is null)
            {
                return null;
            }

            if (!IPAddress.TryParse(answer, out IPAddress? address))
            {
                _reporter.WriteLine("That is not a valid IP address.");
                continue;
            }

            options.QueryName = address.ToString();
            options.ApplyImplicitPtr();
            break;
        }

        return Finish(options);
    }

    private ProbeOptions? BuildCompare()
    {
        // No interface question here: comparing every interface is the whole point of the mode.
        var options = new ProbeOptions { Command = ProbeCommand.Query, Compare = true };

        _reporter.WriteLine();
        _reporter.WriteLine("This sends the same query from every eligible interface and compares them.");
        _reporter.WriteLine();

        if (!AskServer(options, null, required: true))
        {
            return null;
        }

        return AskName(options, "Name to look up: ") ? Finish(options) : null;
    }

    private ProbeOptions? BuildReliability()
    {
        var options = new ProbeOptions { Command = ProbeCommand.Query };

        InterfaceInfo? selected = AskInterface(options, out bool aborted);
        if (aborted)
        {
            return null;
        }

        if (!AskServer(options, selected))
        {
            return null;
        }

        if (!AskName(options, "Name to look up: "))
        {
            return null;
        }

        options.Count = AskNumber("How many queries?", defaultValue: 10, min: 2, max: 1000);
        options.IntervalMilliseconds = AskNumber(
            "Delay between queries in milliseconds?", defaultValue: 1000, min: 0, max: 60000);

        return Finish(options);
    }

    // ---------------------------------------------------------------- shared questions

    private InterfaceInfo? AskInterface(ProbeOptions options, out bool aborted)
    {
        aborted = false;

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
            aborted = true;
            return null;
        }

        _reporter.WriteLine();
        _reporter.WriteLine("Which interface should the query be sent from?");
        _reporter.WriteLine("  [0] Let Windows decide (no interface pinning)");

        for (int i = 0; i < eligible.Count; i++)
        {
            InterfaceInfo nic = eligible[i];
            string addresses = nic.Ipv4Addresses.Count > 0
                ? string.Join(", ", nic.Ipv4Addresses)
                : string.Join(", ", nic.Ipv6Addresses);

            _reporter.WriteLine($"  [{i + 1}] {nic.Name}  {addresses}  ({nic.CategoryLabel})");
        }

        while (true)
        {
            string? answer = Prompt("Choice [0]: ");

            if (answer is null)
            {
                aborted = true;
                return null;
            }

            if (answer.Length == 0)
            {
                return null;
            }

            if (!int.TryParse(answer, NumberStyles.Integer, CultureInfo.InvariantCulture, out int choice)
                || choice < 0
                || choice > eligible.Count)
            {
                _reporter.WriteLine($"Please enter a number between 0 and {eligible.Count}.");
                continue;
            }

            if (choice == 0)
            {
                return null;
            }

            InterfaceInfo selected = eligible[choice - 1];
            options.InterfaceName = selected.Name;
            return selected;
        }
    }

    private bool AskServer(ProbeOptions options, InterfaceInfo? selected, bool required = false)
    {
        string? defaultServer = null;

        if (!required && selected is not null && selected.DnsServers.Count > 0)
        {
            defaultServer = selected.DnsServers[0].ToString();
        }

        while (true)
        {
            string prompt = defaultServer is null
                ? "DNS server IP address: "
                : $"DNS server IP address [{defaultServer}]: ";

            string? answer = Prompt(prompt);

            if (answer is null)
            {
                return false;
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
            return true;
        }
    }

    private bool AskRecordType(ProbeOptions options)
    {
        while (true)
        {
            string? answer = Prompt("Record type [A]: ");

            if (answer is null)
            {
                return false;
            }

            if (answer.Length == 0)
            {
                return true;
            }

            if (!CommandLineParser.TryParseRecordType(answer, out DnsRecordType type))
            {
                _reporter.WriteLine("Unknown record type. Try A, AAAA, CNAME, MX, NS, TXT, PTR, SOA or SRV.");
                continue;
            }

            options.RecordType = type;
            options.RecordTypeExplicit = true;
            return true;
        }
    }

    private bool AskName(ProbeOptions options, string prompt)
    {
        while (true)
        {
            string? answer = Prompt(prompt);

            if (answer is null)
            {
                return false;
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

            return true;
        }
    }

    private bool AskYesNo(string question, bool defaultYes)
    {
        string suffix = defaultYes ? " [Y/n]: " : " [y/N]: ";

        while (true)
        {
            string? answer = Prompt(question + suffix);

            if (answer is null)
            {
                return defaultYes;
            }

            if (answer.Length == 0)
            {
                return defaultYes;
            }

            if (answer.StartsWith('y') || answer.StartsWith('Y'))
            {
                return true;
            }

            if (answer.StartsWith('n') || answer.StartsWith('N'))
            {
                return false;
            }

            _reporter.WriteLine("Please answer y or n.");
        }
    }

    private int AskNumber(string question, int defaultValue, int min, int max)
    {
        while (true)
        {
            string? answer = Prompt($"{question} [{defaultValue}]: ");

            if (answer is null || answer.Length == 0)
            {
                return defaultValue;
            }

            if (int.TryParse(answer, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value)
                && value >= min
                && value <= max)
            {
                return value;
            }

            _reporter.WriteLine($"Please enter a number between {min} and {max}.");
        }
    }

    private ProbeOptions Finish(ProbeOptions options)
    {
        if (options.ServerAddress is not null
            && options.ServerAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            options.ForcedFamily = AddressFamily.InterNetworkV6;
        }

        return options;
    }

    // ---------------------------------------------------------------- teaching the CLI

    /// <summary>
    /// Prints the command line that would produce the same run. This is the most useful thing the
    /// interactive mode does: after a few sessions the user stops needing it.
    /// </summary>
    private void ShowEquivalentCommand(ProbeOptions options)
    {
        var builder = new StringBuilder("dnsprobe");

        if (options.Command == ProbeCommand.ListInterfaces)
        {
            builder.Append(" --interfaces");

            if (options.ShowAllInterfaces)
            {
                builder.Append(" --all");
            }
        }
        else
        {
            if (options.QueryName is not null)
            {
                builder.Append(' ').Append(Quote(options.QueryName));
            }

            if (options.RecordTypeExplicit)
            {
                builder.Append(" --type ").Append(options.RecordType.ToDisplayString());
            }

            if (options.InterfaceName is not null)
            {
                builder.Append(" --interface ").Append(Quote(options.InterfaceName));
            }

            if (options.ServerAddress is not null)
            {
                builder.Append(" --server ").Append(options.ServerAddress);

                if (options.ServerPort != 53)
                {
                    builder.Append('#').Append(options.ServerPort.ToString(CultureInfo.InvariantCulture));
                }
            }

            if (options.Compare)
            {
                builder.Append(" --compare");
            }

            if (options.RouteCheck)
            {
                builder.Append(" --route-check");
            }

            if (options.Count > 1)
            {
                builder.Append(" --count ").Append(options.Count.ToString(CultureInfo.InvariantCulture));

                if (options.IntervalMilliseconds != 1000)
                {
                    builder.Append(" --interval ")
                        .Append(options.IntervalMilliseconds.ToString(CultureInfo.InvariantCulture));
                }
            }

            if (options.Verbose)
            {
                builder.Append(" --verbose");
            }
        }

        _reporter.WriteLine();
        _reporter.WriteLine("Equivalent command:");
        _reporter.WriteLine("  " + builder);
        _reporter.WriteLine();
    }

    private static string Quote(string value) =>
        value.Contains(' ', StringComparison.Ordinal) ? $"\"{value}\"" : value;

    private string? Prompt(string text)
    {
        Console.Out.Write(text);
        Console.Out.Flush();
        return _input.ReadLine()?.Trim();
    }
}
