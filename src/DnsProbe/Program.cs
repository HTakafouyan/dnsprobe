using System.Text;
using DnsProbe;
using DnsProbe.Cli;
using DnsProbe.Diagnostics;
using DnsProbe.Dns;
using DnsProbe.Network;

Console.OutputEncoding = Encoding.UTF8;

var reporter = new DiagnosticReporter();

if (!OperatingSystem.IsWindows())
{
    reporter.WriteWarning(
        "dnsprobe targets Windows. Interface pinning (IP_UNICAST_IF) and routing inspection are "
        + "Windows specific and will not work on this platform.");
}

ParseResult parsed = CommandLineParser.Parse(args);

if (!parsed.Success)
{
    reporter.WriteError(parsed.Error!);
    reporter.WriteLine();
    reporter.WriteLine("Run 'dnsprobe --help' for usage.");
    return ExitCodes.UsageError;
}

ProbeOptions options = parsed.Options!;

switch (options.Command)
{
    case ProbeCommand.Help:
        reporter.WriteLine(HelpText.Build());
        return ExitCodes.Success;

    case ProbeCommand.Version:
        reporter.WriteLine(HelpText.BuildVersion());
        return ExitCodes.Success;
}

// --help and --version stay human readable; everything after this point honours --json.
if (options.Json)
{
    // JSON mode owns stdout: the human readable reporter must stay completely silent.
    reporter = new DiagnosticReporter(TextWriter.Null, TextWriter.Null);
}
else
{
    // Colour is decided after parsing so that --no-color can veto the auto-detection.
    reporter.UseColor = !options.NoColor && ConsoleTheme.DetectSupport();
}

var provider = new SystemNetworkInterfaceProvider();

if (options.Command == ProbeCommand.Interactive)
{
    var session = new InteractiveSession(provider, reporter);
    ProbeOptions? interactive = session.Run();

    if (interactive is null)
    {
        reporter.WriteLine("Aborted.");
        return ExitCodes.UsageError;
    }

    options = interactive;
}

using var cancellation = new CancellationTokenSource();

Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellation.Cancel();
};

var runner = new ProbeRunner(provider, reporter, new DnsClient(new SocketFactory()), new RouteInspector());

try
{
    return await runner.RunAsync(options, cancellation.Token).ConfigureAwait(false);
}
catch (OperationCanceledException)
{
    reporter.WriteLine();
    reporter.WriteLine("Cancelled.");
    return ExitCodes.NoResponse;
}
catch (SocketConfigurationException ex)
{
    return Report(ex.Message, ExitCodes.UsageError);
}
catch (DnsProtocolException ex)
{
    return Report(ex.Message, ExitCodes.UsageError);
}
catch (Exception ex)
{
    // Last line of defence: a diagnostic tool must never dump a raw stack trace at the user.
    return Report($"Unexpected failure: {ex.GetType().Name}: {ex.Message}", ExitCodes.NoResponse);
}

int Report(string message, int exitCode)
{
    if (options.Json)
    {
        JsonOutput.WriteError(message, exitCode);
    }
    else
    {
        reporter.WriteError(message);
    }

    return exitCode;
}
