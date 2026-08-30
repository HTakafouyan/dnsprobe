namespace DnsProbe.Cli;

public static class HelpText
{
    public const string Version = "1.0.0";

    public static string Build() => """
dnsprobe - DNS diagnostics with explicit interface and source IP selection

USAGE
  dnsprobe <name> [options]
  dnsprobe <ip-address> [--type PTR] [options]
  dnsprobe --interfaces [--all]
  dnsprobe                     (interactive mode)
  dnsprobe --help | --version

QUERY
  -t, --type <type>            A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV, ANY or TYPEnnn.
                               Defaults to A, or to PTR when the argument is an IP address.
      --no-recurse             Clear the RD (recursion desired) flag.

INTERFACE / SOURCE SELECTION
  -i, --interface <name>       Send the query from this adapter, e.g. "Ethernet 2".
      --interface-index <n>    Send the query from this interface index.
      --source-ip <ip>         Bind the socket to this local address.
      --allow-down             Proceed even if the selected adapter is not operational.
      --no-unicast-if          Do not set IP_UNICAST_IF / IPV6_UNICAST_IF; bind only.
                               Useful for demonstrating the difference between binding a source
                               address and actually pinning the egress interface.

EDNS(0)
      --edns [size]            Send an EDNS(0) OPT record advertising a UDP payload size
                               (default 1232, range 512-4096). EDNS is on by default.
      --no-edns                Send a plain RFC 1035 query with no OPT record.
      --dnssec                 Set the DO bit to request DNSSEC records. Implies EDNS.
      --nsid                   Ask the server to identify itself (NSID). Implies EDNS.

DNS SERVER
  -s, --server <ip[#port]>     DNS server to query. IPv6 literals may be written [addr]:port.
      --port <n>               Destination port (default 53).
      --system-dns             Use the DNS servers configured on the selected interface.

TRANSPORT
      --protocol <udp|tcp>     Transport to use (default udp).
      --udp / --tcp            Shorthands for the above.
      --tcp-fallback           Repeat the query over TCP when the UDP answer has TC=1.
  -4, --ipv4                   Force IPv4.
  -6, --ipv6                   Force IPv6.

TIMING
      --timeout <ms>           Per attempt timeout (default 2000).
      --retries <n>            Additional attempts after the first one (default 1).
  -c, --count <n>              Repeat the whole query n times and print statistics.
      --interval <ms>          Delay between repeated queries (default 1000).

DIAGNOSTICS
  -v, --verbose                Show the full probe header, flags and every section.
      --debug                  Also print packet hex dumps. Implies --verbose.
      --route-check            Show what the Windows routing table would do for this destination.
      --compare                Run the same query from every eligible interface and compare.
      --interfaces             List the network interfaces and exit.
      --all                    With --interfaces: also show loopback and inactive adapters.
      --json                   Emit one JSON document instead of human readable output.
                               Implies --no-color.
      --no-color               Plain output with no ANSI colour. Colour is also disabled
                               automatically when the output is redirected, or when the
                               NO_COLOR environment variable is set.

EXAMPLES
  dnsprobe example.com
  dnsprobe example.com --interface "Ethernet 2"
  dnsprobe example.com --source-ip 10.10.10.20
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --type AAAA
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --tcp
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --count 10
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --verbose --route-check
  dnsprobe example.com --server 10.10.10.53 --compare
  dnsprobe 8.8.8.8 --type PTR --server 1.1.1.1
  dnsprobe example.com --server 8.8.8.8 --dnssec --verbose
  dnsprobe example.com --server 8.8.8.8 --nsid --verbose
  dnsprobe example.com --server 8.8.8.8 --json

EXIT CODES
  0  a DNS response with RCODE=NOERROR was received
  1  a DNS response with a non-zero RCODE was received
  2  no usable response (timeout, unreachable, malformed)
  3  invalid command line or invalid interface/source selection
""";

    public static string BuildVersion() =>
        $"dnsprobe {Version} - DNS diagnostics with explicit interface and source IP selection";
}
