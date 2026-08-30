using System.Globalization;
using DnsProbe.Network;

namespace DnsProbe.Diagnostics;

/// <summary>
/// Colour policy for the console output.
///
/// Colour is a readability aid, never a carrier of meaning on its own: every coloured value is
/// also readable as plain text, so the output stays correct when colour is disabled, redirected
/// to a file, or read by a screen reader.
/// </summary>
public sealed class ConsoleTheme
{
    private const string Reset = "\u001b[0m";
    private const string RedCode = "\u001b[31m";
    private const string GreenCode = "\u001b[32m";
    private const string YellowCode = "\u001b[33m";
    private const string CyanCode = "\u001b[96m";
    private const string DimCode = "\u001b[90m";
    private const string BoldCode = "\u001b[1m";

    /// <summary>Round trip times below this are shown in green.</summary>
    public const double FastMilliseconds = 50;

    /// <summary>Round trip times below this are shown in yellow; above it, red.</summary>
    public const double SlowMilliseconds = 200;

    public ConsoleTheme(bool enabled)
    {
        Enabled = enabled;
    }

    public bool Enabled { get; }

    // ---------------------------------------------------------------- primitives

    private string Wrap(string code, string text) => Enabled ? code + text + Reset : text;

    /// <summary>Everything is fine: successful results, NOERROR, reachable interfaces.</summary>
    public string Good(string text) => Wrap(GreenCode, text);

    /// <summary>A definite failure: timeouts, SERVFAIL, unreachable networks.</summary>
    public string Bad(string text) => Wrap(RedCode, text);

    /// <summary>An answer arrived but deserves a second look: REFUSED, NXDOMAIN, warnings, notes.</summary>
    public string Caution(string text) => Wrap(YellowCode, text);

    /// <summary>A value the user explicitly chose: interface, index, source IP, pinning.</summary>
    public string Selected(string text) => Wrap(CyanCode, text);

    /// <summary>Field names, separators and other chrome that should recede.</summary>
    public string Label(string text) => Wrap(DimCode, text);

    /// <summary>Section headings.</summary>
    public string Heading(string text) => Wrap(BoldCode, text);

    // ---------------------------------------------------------------- semantic helpers

    /// <summary>Colours a round trip time by how slow it is.</summary>
    public string RoundTrip(double milliseconds)
    {
        string text = DiagnosticReporter.FormatMilliseconds(milliseconds);

        if (milliseconds < FastMilliseconds)
        {
            return Good(text);
        }

        return milliseconds < SlowMilliseconds ? Caution(text) : Bad(text);
    }

    /// <summary>
    /// Colours an outcome or response-code label, padded to <paramref name="width"/> characters
    /// before the escape codes are added so that table columns stay aligned.
    /// </summary>
    public string Outcome(string label, int width = 0)
    {
        string padded = width > 0 ? label.PadRight(width) : label;

        return label switch
        {
            "SUCCESS" or "NOERROR" => Good(padded),
            "REFUSED" or "NXDOMAIN" or "NODATA" or "TRUNCATED" => Caution(padded),
            _ => Bad(padded),
        };
    }

    /// <summary>Colours a loss percentage.</summary>
    public string Loss(double percentage) => percentage switch
    {
        <= 0 => Good("0%"),
        < 100 => Caution(percentage.ToString("0.#", CultureInfo.InvariantCulture) + "%"),
        _ => Bad("100%"),
    };

    /// <summary>Colours an adapter status.</summary>
    public string Status(bool isUp, string text) => isUp ? Good(text) : Label(text);

    /// <summary>Highlights adapter kinds that are easy to pick by mistake.</summary>
    public string Category(InterfaceCategory category, string text) => category switch
    {
        InterfaceCategory.Vpn or InterfaceCategory.Tunnel => Caution(text),
        InterfaceCategory.HyperV or InterfaceCategory.ContainerOrWsl or InterfaceCategory.VirtualMachine
            => Label(text),
        _ => text,
    };

    // ---------------------------------------------------------------- detection

    /// <summary>
    /// Decides whether colour should be used at all. Redirected output must stay clean, because
    /// escape codes in a log file are worse than no colour at all.
    /// </summary>
    public static bool DetectSupport()
    {
        try
        {
            if (Console.IsOutputRedirected)
            {
                return false;
            }
        }
        catch (IOException)
        {
            return false;
        }

        // https://no-color.org - any non-empty value disables colour.
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR")))
        {
            return false;
        }

        if (string.Equals(Environment.GetEnvironmentVariable("TERM"), "dumb", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            return NativeMethods.TryEnableVirtualTerminalProcessing();
        }

        return true;
    }
}
