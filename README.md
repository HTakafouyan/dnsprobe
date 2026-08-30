# dnsprobe

A Windows DNS diagnostic tool that lets you choose **which network interface and which source IP address** a DNS query originates from.

`dnsprobe` speaks the DNS protocol itself. It builds and parses the packets, opens the socket, binds it, and pins it to an interface. It never shells out to `nslookup.exe`, `Resolve-DnsName` or `System.Net.Dns`.

**Requirements:** Windows 10 / 11 / Server 2016 or newer, x64. .NET 8 to build; the published
binary can be self-contained and needs nothing installed. No administrator rights required.
The interface pinning and routing inspection are Windows-specific, so this tool is Windows-only by
design.

**Status:** the tool is complete and has been exercised against real multi-homed machines,
VPN tunnels and intercepting resolvers. See [Testing](#17-testing) for what is covered.

---

## Contents

1. [What the tool does](#1-what-the-tool-does)
2. [Why nslookup is not enough](#2-why-nslookup-is-not-enough)
3. [Build and install](#3-build-and-install)
4. [Usage](#4-usage)
5. [Interface selection](#5-interface-selection)

The remaining sections cover source IP selection, DNS server selection, UDP/TCP, IPv4/IPv6,
routing behaviour, limitations, troubleshooting, Wireshark verification, security, architecture
and testing.

---

## 1. What the tool does

* Lists every network adapter with its index, addresses, gateways and configured DNS servers.
* Sends a real DNS query (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV, or any numeric type) over UDP or TCP.
* Binds the socket to a source IP **and** pins it to an interface index with `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.
* Shows the local endpoint, the remote endpoint, the transaction ID, RTT, flags and the full response.
* Inspects the real Windows routing table (`GetBestRoute2`, `GetBestInterfaceEx`) and warns when your selection disagrees with it.
* Runs the same query from **every** eligible interface and compares the results (`--compare`).
* Repeats a query and reports loss / min / max / average / jitter (`--count`).
* Dumps the raw packets in hex (`--debug`).

## 2. Why `nslookup` is not enough

`nslookup` lets you choose the *server* (`nslookup example.com 10.10.10.53`), but it gives you no control over the *client* side of the socket:

| Question | `nslookup` | `dnsprobe` |
|---|---|---|
| Which DNS server do I ask? | yes | yes |
| Which local IP is the query sent **from**? | no | `--source-ip` |
| Which adapter does the packet leave through? | no | `--interface` / `--interface-index` |
| Does the routing table agree with my choice? | no | `--route-check` |
| Which of my 5 NICs can actually reach this resolver? | no | `--compare` |

On a box with a LAN NIC, a VLAN sub-interface, a VPN tunnel, a Hyper-V switch and Wi-Fi all up at once, "the DNS server does not answer" is almost never a DNS problem — it is a *path* problem. `nslookup` cannot show you the path. That is the gap this tool fills.

## 3. Installation and build

Requirements: Windows 10/11 or Windows Server 2016+, and the .NET SDK (8.0 LTS or newer).

```powershell
git clone <this repo>
cd DnsProbe

dotnet build -c Release
dotnet test

# self-contained single file, no .NET runtime needed on the target machine
dotnet publish src/DnsProbe/DnsProbe.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true -o publish
```

The executable is named `dnsprobe.exe`.

The projects target `net8.0-windows`. If you have the .NET 10 (LTS) SDK, change `<TargetFramework>` in `src/DnsProbe/DnsProbe.csproj` and `tests/DnsProbe.Tests/DnsProbe.Tests.csproj` to `net10.0-windows`; no source changes are needed.

No third-party runtime dependencies. The test project uses xunit.

**Administrator rights are not required.** Binding a source address, setting `IP_UNICAST_IF` and sending UDP/TCP to port 53 are all unprivileged operations.

## 4. Usage

```
dnsprobe <name> [options]
dnsprobe <ip-address> [--type PTR] [options]
dnsprobe --interfaces [--all]
dnsprobe                       (interactive mode)
dnsprobe --help | --version
```

Run `dnsprobe --help` for the complete option list.

### Listing interfaces

```
> dnsprobe --interfaces

Available Network Interfaces
----------------------------------------
[1] Ethernet
    Description : Intel(R) Ethernet Controller
    Kind        : Ethernet (physical) (Ethernet)
    Status      : Up
    Index       : IPv4 12, IPv6 12
    IPv4        : 192.168.1.20
    IPv6        : fe80::a1b2:c3d4:e5f6:1
    Gateway     : 192.168.1.1
    DNS         : 192.168.1.1

[2] Ethernet 2
    Description : Intel(R) Ethernet Controller #2
    Kind        : Ethernet (physical) (Ethernet)
    Status      : Up
    Index       : IPv4 15, IPv6 15
    IPv4        : 10.10.10.20
    Gateway     : 10.10.10.1
    DNS         : 10.10.10.53
```

Loopback and inactive adapters are hidden unless you pass `--all`. Hyper-V, Docker/WSL, VPN, VMware and tunnel adapters are labelled in the `Kind` line.

### A verbose probe

```
> dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --verbose

DNS Probe
----------------------------------------
Query           : example.com
Record Type     : A
Protocol        : UDP
Address Family  : IPv4
Interface       : Ethernet 2
Interface Index : 15
Source IP       : 10.10.10.20
DNS Server      : 10.10.10.53
Server Source   : command line (--server)
Destination Port: 53
Timeout         : 2000 ms
Retries         : 1
Interface Pin   : IP_UNICAST_IF

Sending query...
Local endpoint  : 10.10.10.20:53142
Remote endpoint : 10.10.10.53:53
Response received.
Round Trip Time : 7.10 ms
Transaction ID  : 0xA31F
Response Code   : NOERROR
Transport       : UDP
Flags           : qr rd ra
  Authoritative : no
  Truncated     : no
  Recursion Des.: yes
  Recursion Av. : yes
Counts          : 1 question, 1 answer, 0 authority, 0 additional

Answer:
  example.com. -> 93.184.216.34
    Type        : A
    TTL         : 300 s
```

### Comparing every interface

```
> dnsprobe example.com --server 10.10.10.53 --compare

Interface                Source IP                Result         RTT
----------------------------------------------------------------------------
Ethernet                 192.168.1.20             TIMEOUT        -
Ethernet 2               10.10.10.20              SUCCESS        4.20 ms
VPN                      10.20.30.10              REFUSED        12.00 ms
```

This is the fastest way to answer "which of my paths can reach this resolver, and is it being blocked or just black-holed?".

### Repeated queries

```
> dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --count 5

Query 1: 8.10 ms
Query 2: 7.30 ms
Query 3: TIMEOUT
Query 4: 9.00 ms
Query 5: 7.60 ms

Statistics
----------------------------------------
Sent     : 5
Received : 4
Lost     : 1 (20%)
Min      : 7.30 ms
Max      : 9.00 ms
Average  : 8.00 ms
Jitter   : 0.60 ms
```

### EDNS(0)

EDNS(0) (RFC 6891) is on by default. It attaches a small OPT pseudo-record to the query that
advertises how large a UDP answer this client can accept, which lifts the 512 byte limit that plain
RFC 1035 DNS imposes and avoids a slow fallback to TCP.

```powershell
dnsprobe example.com --server 8.8.8.8 --verbose          # EDNS on, 1232 byte payload
dnsprobe example.com --server 8.8.8.8 --edns 4096        # advertise a larger buffer
dnsprobe example.com --server 8.8.8.8 --no-edns          # plain RFC 1035 query
dnsprobe example.com --server 8.8.8.8 --dnssec           # set the DO bit
dnsprobe example.com --server 8.8.8.8 --nsid             # ask the server to identify itself
```

The default advertised size is 1232 bytes. That number is not arbitrary: it keeps the response
below the smallest MTU IPv6 guarantees, so the answer never has to be fragmented. Fragmented DNS
is both a reliability and a security problem, so bigger is not better here. The accepted range is
512 to 4096.

What the server sends back is reported too:

```
EDNS            : version 0, UDP payload 1232, DO
EDNS Response   : version 0, UDP payload 1232, DO
Server NSID     : dns-node-7
Extended Error  : 6 (DNSSEC Bogus) - signature verification failed
```

Three of those are worth calling out:

* **Extended DNS Errors** (RFC 8914) turn a bare `SERVFAIL` into an actual explanation - expired
  signature, unreachable upstream, blocked by policy, and so on. They are shown even without
  `--verbose`, because they are usually the whole answer to "why did this fail".
* **NSID** (RFC 5001) tells you *which* server answered. Behind an anycast address or a load
  balancer, that is often the only way to tell one backend from another.
* **The extended RCODE** adds 8 bits to the 4 bit header code, which is how codes such as
  `BADVERS` can be reported at all.

Some firewalls and older resolvers mishandle queries carrying an OPT record. When an EDNS query
times out or comes back `FORMERR`/`NOTIMP`, dnsprobe automatically repeats it without EDNS and
tells you what it found:

```
Notes:
  - The query with an EDNS(0) OPT record failed, but the same query without EDNS succeeded.
    Something on this path does not tolerate EDNS - use --no-edns here.
```

That is a diagnosis in itself: it means something between you and the server is breaking EDNS.

### JSON output

`--json` replaces all human readable output with a single JSON document, for monitoring scripts and
scheduled checks. Nothing else is written to stdout, and the exit code is unchanged.

```powershell
dnsprobe example.com --server 10.10.10.53 --json
dnsprobe example.com --server 10.10.10.53 --count 10 --json
dnsprobe example.com --server 10.10.10.53 --compare --json
dnsprobe --interfaces --json
```

Every document carries `tool`, `version`, `timestamp`, `status` and `exitCode`. Consumers should
branch on `status` and `exitCode` rather than parsing any prose fields. A failure - including a
usage error - is also reported as JSON:

```json
{
  "tool": "dnsprobe",
  "status": "error",
  "exitCode": 3,
  "error": "Source IP 192.168.1.20 does not belong to interface \"Ethernet 2\"."
}
```

A successful query adds `query`, `probe` and `response` objects; `--count` replaces `response`
with `statistics`; `--compare` replaces it with `results`, one entry per interface.

### Observations

Some things are visible in a response but are not errors, so they do not belong in the warning
stream. dnsprobe collects them into an `Observations` block:

```
Observations
----------------------------------------
  - An EDNS(0) OPT record was sent but the response carried none. A server that supports EDNS is
    required to echo one, so either this server is old, or something between you and it rewrote
    the response. Compare with --tcp and with a different server.
```

The checks made from a single response are: an EDNS query answered without an OPT record, an
answer truncated despite a large advertised payload size, a server advertising a UDP payload above
1500 bytes (which will be fragmented on most links), and recursion requested but unavailable.

With `--count` there is one more, and it is the most useful of them: whether the TTL counts down
between queries. A caching resolver decrements it, so a TTL that never moves suggests the answer is
being generated rather than served from a real cache.

That check is skipped entirely when any response has `aa=1`. An authoritative server reads the TTL
straight out of its zone file and never counts it down, so applying the check there would produce a
false alarm on every correctly configured internal DNS server. It also needs a window of at least
five seconds; below that it says so instead of guessing. To get a clean signal:

```powershell
dnsprobe example.com --server 8.8.8.8 --count 10 --interval 2000
```

Every one of these is a heuristic. The wording says "suggests" rather than "is", on purpose - a
diagnostic tool that overstates its conclusions is worse than one that stays quiet, because people
act on what it says. They tell you where to look next; they do not decide for you.

### Colour and the closing summary

Output is colour coded when the console supports it: green for successful results, red for definite
failures, yellow for answers that arrived but deserve a second look (REFUSED, NXDOMAIN, truncation,
warnings, notes), and cyan for the values you selected yourself — interface, interface index and
source IP. Round trip times are green below 50 ms, yellow below 200 ms and red above that.

Every run ends with a single `RESULT:` line so you do not have to re-read the output to find out
what happened:

```
RESULT: OK - 10.10.10.90 in 14.8 ms via Ethernet 2 (10.10.10.20)
RESULT: NODATA - no MX record for example.com (13.4 ms)
RESULT: TIMEOUT - no usable answer from 10.10.10.53 via Ethernet (192.168.1.20)
RESULT: OK - 10/10 received, avg 46.5 ms via Ethernet 2 (10.10.10.20)
RESULT: PARTIAL - 1 of 3 interface(s) reached 8.8.8.8: Wi-Fi
```

Colour is never the only carrier of meaning — the same information is in the text — so nothing is
lost when it is switched off. It is disabled automatically when the output is redirected to a file
or a pipe, when the `NO_COLOR` environment variable is set, or when the console does not support
ANSI escape sequences. `--no-color` forces it off explicitly.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | response received, `RCODE = NOERROR` |
| 1 | response received with a non-zero RCODE (SERVFAIL, NXDOMAIN, REFUSED, …) |
| 2 | no usable response (timeout, unreachable, malformed) |
| 3 | invalid command line, or an impossible interface/source selection |

## 5. Interface selection

```
dnsprobe example.com --interface "Ethernet 2"
dnsprobe example.com --interface-index 15
```

`--interface` matches, in this order: the exact connection name, the exact adapter description, the adapter GUID, then a unique substring of the name or description. An ambiguous match is an error, never a guess.

The chosen adapter must be operational; `--allow-down` overrides that.

## 6. Source IP selection

```
dnsprobe example.com --source-ip 10.10.10.20
```

If you give only `--source-ip`, the owning interface is looked up for you. If you give both, they are cross-checked:

```
> dnsprobe example.com --interface "Ethernet 2" --source-ip 192.168.1.20
ERROR: Source IP 192.168.1.20 does not belong to interface "Ethernet 2". It is configured on "Ethernet".
```

If an interface has several addresses of the chosen family, the first non-link-local one is used and you are told about it, so you can override with `--source-ip`.

## 7. DNS server selection

```
dnsprobe example.com --server 10.10.10.53
dnsprobe example.com --server 10.10.10.53#5353
dnsprobe example.com --server 2001:4860:4860::8888
dnsprobe example.com --server "[2001:db8::1]:5353"
dnsprobe example.com --interface "Ethernet 2" --system-dns
```

The server must be an IP address. `dnsprobe` deliberately refuses to resolve a server *name*, because doing so would require the very resolver you are trying to diagnose.

With `--system-dns` (or with no `--server` at all) the tool reports where the server came from:

```
DNS Server      : 10.10.10.53
Server Source   : DNS configuration of Ethernet 2
```

**If you selected an interface, only that interface's DNS servers are considered.** If it has none for the chosen family, you get an error rather than a silent fallback to another adapter's resolver — silently querying `192.168.1.1` while you asked for `Ethernet 2` would invalidate the whole test.

## 8. UDP and TCP

```
dnsprobe example.com --protocol udp        # default
dnsprobe example.com --protocol tcp
dnsprobe example.com --tcp                 # shorthand
dnsprobe example.com --tcp-fallback        # retry over TCP if TC=1
```

DNS over TCP uses the two-byte big-endian length prefix from RFC 1035 §4.2.2. The reader loops until exactly that many bytes have arrived, and a premature close is reported as such.

EDNS(0) is enabled by default and advertises a 1232 byte UDP buffer, so most large answers arrive over UDP. With `--no-edns` the classic 512 byte limit applies again and large answers come back with `TC=1`; use `--tcp-fallback` or `--tcp` for those.

## 9. IPv4 and IPv6

`--ipv4` / `--ipv6` force a family. Otherwise it is inferred, in order, from `--source-ip`, then `--server`, then defaults to IPv4.

Families are never mixed: a v6 socket is created with `DualMode = false`, and any v4/v6 combination that cannot work is rejected up front with an explanation.

IPv6 link-local sources are accepted but flagged, because link-local traffic is only meaningful inside the scope of one interface.

## 10. Routing behaviour — and the part everyone gets wrong

This is the core of the tool, so it is worth being precise.

### Four different things

1. **Source IP selection** — which address goes into the source field of the IP header.
2. **Interface selection** — which adapter the frame is actually handed to.
3. **The Windows routing decision** — which route entry Windows picks for the destination, based on longest prefix match and then metric.
4. **Next-hop selection** — the gateway MAC the frame is addressed to, or "on-link" if the destination is directly connected.

They are not the same thing, and controlling one does not control the others.

### What `Socket.Bind()` really does

`Socket.Bind(new IPEndPoint(10.10.10.20, 0))` fixes the **source address** of the socket. It does **not** tell the TCP/IP stack which interface to use. On a weak-host-model stack — and Windows is weak-host for *sending* on a per-interface basis — the route lookup still happens against the full routing table. If the best route for `10.10.10.53` points out of `Ethernet`, the packet can leave through `Ethernet` carrying `10.10.10.20` as its source. That is exactly the situation that produces "I bound to the right IP and still got no answer".

So this claim, which you will see in a lot of sample code, is **false**:

> "Binding the source IP guarantees the packet will leave through this interface."

`dnsprobe` does not make that claim anywhere.

### What actually pins the interface

Windows exposes a socket option for this:

* IPv4: `IP_UNICAST_IF` (option 31, level `IPPROTO_IP`)
* IPv6: `IPV6_UNICAST_IF` (option 31, level `IPPROTO_IPV6`)

Setting it makes the stack perform the route lookup **constrained to that interface**, which is the supported user-mode way of forcing outbound unicast traffic onto a specific adapter.

There is a byte-order trap that silently breaks naive implementations:

| Option | Byte order of the interface index |
|---|---|
| `IP_UNICAST_IF` (IPv4) | **network** byte order |
| `IPV6_UNICAST_IF` (IPv6) | **host** byte order |

Passing the wrong one does not fail — it pins the socket to a nonsense interface index. See `SocketFactory.ApplyUnicastInterface` for the implementation.

### What dnsprobe does

For every query it applies **both** mechanisms, in this order:

1. `setsockopt(IP_UNICAST_IF / IPV6_UNICAST_IF, index)` — chooses the egress interface.
2. `Socket.Bind(sourceIp, 0)` — chooses the source address and a random ephemeral source port.

Then, with `--route-check`, it asks Windows what it *would* have done:

```
Route Check
----------------------------------------
Destination : 10.10.10.53
Source      : 10.10.10.20
Interface   : Ethernet 2
Gateway     : On-link
Route Egress: Ethernet 2 (index 15, metric 271)
Route Source: 10.10.10.20 (what Windows would pick without an explicit bind)
```

and warns when the routing table disagrees with your selection:

```
WARNING: The routing table would send traffic for 10.10.10.53 out of interface index 12,
but you selected index 15 ("Ethernet 2"). The IP_UNICAST_IF/IPV6_UNICAST_IF socket option
overrides this, so the packet should still leave through your interface - verify with
Wireshark, and expect no reply if that path cannot reach the server.
```

Routing data comes from `GetBestRoute2` and `GetBestInterfaceEx` in `iphlpapi.dll`. Nothing is invented: if the API fails, the tool prints the Win32 error and says routing information is unavailable.

Use `--no-unicast-if` to disable the pinning and see for yourself what plain source binding does. That flag exists specifically to demonstrate the difference described above.

## 11. Limitations — stated honestly

* **Verification is your job, and Wireshark is the referee.** `dnsprobe` reports the socket's local endpoint and the option it set; it cannot observe the wire. See §13.
* Pinning the interface does not create connectivity. If that path cannot reach the resolver, you get a timeout — which is usually the answer you were looking for.
* Policy-based routing, third-party WFP/LSP filter drivers, VPN clients that redirect traffic in the kernel, and NRPT rules can all override or reroute what the socket asked for. Such drivers are outside anything a user-mode tool can inspect.
* EDNS(0) is supported for payload size, the DO bit, NSID and Extended DNS Errors. Other EDNS
  options (cookies, client subnet, padding) are preserved but not decoded.
* DNSSEC records can be requested with `--dnssec` and are displayed, but signatures are **not**
  validated - that is a resolver's job, not a probe's.
* No DoT/DoH/DoQ, no zone transfers.
* The routing structures are read through documented `iphlpapi` APIs at fixed field offsets, which are correct for x86/x64/ARM64 Windows; a future change to `MIB_IPFORWARD_ROW2` would require updating `NativeMethods`.
* `--compare` sends one query per interface sequentially, so it is not a load test.
* Interface classification (VPN / Hyper-V / Docker / WSL) is a keyword heuristic. Windows does not expose "this is a VPN adapter" as a first-class property.

## 12. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `DNS request timed out.` | The path exists but nothing answers: firewall, ACL, or wrong VLAN. Try `--compare`. |
| `... replied with ICMP port unreachable` | You reached the host, but no DNS service is listening on that port. |
| `Network is unreachable` / `NET-UNREACH` | No route from the bound source address. Run with `--route-check`. |
| `PORT-UNREACH` | The host answered with ICMP port unreachable: it exists, but no DNS service is listening. A socket-level result, not a DNS one. |
| `IF-UNREACH` | The interface you pinned has no route to the server. Windows reports this as WSAEINVAL because `IP_UNICAST_IF` forbids falling back to another interface. Re-run with `--no-unicast-if` to see what routing would have done. |
| `DNS server returned REFUSED` | You reached a real DNS server; it refuses queries from your source IP. This is an ACL, not a network fault. |
| `DNS server returned SERVFAIL` | Server-side failure: broken forwarder, DNSSEC failure, unreachable upstream. |
| `Source IP … does not belong to interface …` | Exactly what it says. Check `--interfaces`. |
| `Interface "X" has no IPv4 address` | DHCP failed, or the adapter is IPv6-only. |
| `Could not pin the socket to interface index …` | Retry with `--no-unicast-if`, and report the socket error. |
| Response is truncated (`TC=1`) | Add `--tcp-fallback` or `--tcp`. |

`PORT-UNREACH` and `REFUSED` are deliberately different labels. `REFUSED` is the DNS RCODE: a real
DNS server received the query and declined to answer it, almost always because of an ACL on the
source address. `PORT-UNREACH` happens one layer lower - the packet reached the host, but nothing
was listening on UDP/53, so no DNS conversation took place at all. The fix is different in each
case, so the tool never uses one name for both.

## 13. Verifying with Wireshark (do not skip this)

This is the only way to *prove* the packet left where you wanted it to.

Test bed:

```
NIC 1  "Ethernet"     192.168.1.20/24   gateway 192.168.1.1
NIC 2  "Ethernet 2"   10.10.10.20/24    gateway 10.10.10.1
DNS server           10.10.10.53
```

1. Start Wireshark and select the **`Ethernet 2`** adapter (capture on the specific NIC, not on "any").
2. Apply the display filter:

   ```
   udp.port == 53
   ```

   For TCP tests use `tcp.port == 53`, and for both: `udp.port == 53 || tcp.port == 53`.
3. Run:

   ```powershell
   dnsprobe.exe example.com --interface "Ethernet 2" --server 10.10.10.53 --verbose
   ```
4. In the captured query packet, confirm:

   * **Source IP = 10.10.10.20** (the address of `Ethernet 2`)
   * **Destination IP = 10.10.10.53**
   * **Destination port = 53**
   * **Source port** matches the `Local endpoint` line printed by the tool
   * The DNS **Transaction ID** matches the one printed by the tool

   A useful precise filter:

   ```
   ip.src == 10.10.10.20 && ip.dst == 10.10.10.53 && udp.dstport == 53
   ```
5. Now capture on **`Ethernet`** at the same time and confirm that **nothing** appears there. That negative result is the real proof of interface selection.
6. Repeat the run with `--no-unicast-if`. On a machine whose routing table prefers the other NIC, you will see the difference between binding a source address and pinning an interface — which is the whole point of §10.

You can also cross-check the local endpoint while a `--count 20` run is in progress:

```powershell
Get-NetUDPEndpoint | Where-Object LocalAddress -eq '10.10.10.20'
```

## 14. Security considerations

DNS responses are unauthenticated data from the network and are treated as hostile:

* Every read is bounds-checked before it happens; `RDLENGTH` is validated against the remaining buffer.
* Name decoding is **iterative**, not recursive — no stack overflow is possible.
* A compression pointer must point **strictly backwards**. That single rule makes pointer loops impossible; a jump counter and a 255-byte total-length cap are layered on top.
* The two reserved label-type bit patterns are rejected rather than ignored.
* The record cursor always advances by `RDLENGTH`, so a lying RDATA cannot desynchronise the parser. A single undecodable record degrades to a raw record plus a warning instead of failing the message.
* Transaction IDs come from `RandomNumberGenerator`, and the source port is a random ephemeral port; responses with the wrong ID, the wrong sender endpoint, or a length below 12 bytes are discarded and counted.
* Labels are escaped (`\ddd`) before display, so a hostile name cannot inject control characters into your terminal.
* No `unsafe` code anywhere. Native buffers are handled through `Marshal` with explicit sizes and are always freed in a `finally`.
* The tool only ever *sends* queries; it never opens a listening socket.
* A fuzz-style test feeds 500 random byte arrays to the parser and asserts that nothing but `DnsProtocolException` escapes.

## 15. Architecture

```
DnsProbe/
├── DnsProbe.sln
├── src/DnsProbe/
│   ├── Program.cs                     entry point, top-level error handling
│   ├── ProbeRunner.cs                 orchestration + exit codes
│   ├── Cli/
│   │   ├── ProbeOptions.cs            the validated command line
│   │   ├── CommandLineParser.cs       parsing + combination validation
│   │   ├── HelpText.cs
│   │   └── InteractiveSession.cs      the zero-argument experience
│   ├── Network/
│   │   ├── InterfaceInfo.cs           adapter snapshot (plain data)
│   │   ├── NetworkInterfaceProvider.cs  real enumeration + classification
│   │   ├── InterfaceSelector.cs       name/index/source-IP resolution
│   │   ├── SocketFactory.cs           Bind() + IP_UNICAST_IF / IPV6_UNICAST_IF
│   │   ├── RouteInspector.cs          GetBestRoute2 / GetBestInterfaceEx
│   │   └── NativeMethods.cs           P/Invoke, no unsafe
│   ├── Dns/
│   │   ├── DnsEnums.cs, DnsMessage.cs, DnsRecord.cs
│   │   ├── DnsName.cs                 safe encode/decode
│   │   ├── DnsPacketBuilder.cs        query construction + TCP framing
│   │   ├── DnsPacketParser.cs         defensive response decoding
│   │   ├── DnsQuery.cs                request/result model
│   │   └── DnsClient.cs               UDP/TCP transport, retries, fallback
│   └── Diagnostics/
│       ├── DiagnosticReporter.cs      all console output
│       ├── QueryStatistics.cs
│       ├── InterfaceComparer.cs       --compare
│       └── HexDump.cs                 --debug
└── tests/DnsProbe.Tests/
    ├── PacketWriter.cs                synthetic packet builder
    ├── DnsPacketBuilderTests.cs
    ├── DnsPacketParserTests.cs
    ├── DnsNameTests.cs
    ├── InterfaceSelectorTests.cs
    └── CommandLineParserTests.cs
```

Design rules: DNS parsing knows nothing about sockets; the network layer knows nothing about the console; all output lives in `DiagnosticReporter`; interface selection is pure logic behind `INetworkInterfaceProvider`, which is why it can be unit-tested against a synthetic five-NIC machine.

## 16. Tests

```powershell
dotnet test
```

Covered: query construction for A/AAAA/MX/PTR/NS/SOA, TCP framing, name encoding incl. IDN, oversized and empty labels; response parsing for single and multiple answers, CNAME chains with compression, MX/TXT/SOA/PTR RDATA, every response code, the truncated flag, short messages, lying `RDLENGTH`, forward and self-referencing and mutual compression pointers, reserved label types, unknown record types, and a 500-iteration random-input fuzz test; interface lookup by name, exact-over-partial matching, lookup by index, name/index conflicts, source-IP ownership validation, adapters without IPv4, down adapters, family inference and mismatch; and the full CLI surface including every invalid combination.

Integration testing against real hardware is described in §13 and cannot be automated here — it needs two NICs and a packet capture.

## 18. Licence

MIT. See [LICENSE](LICENSE).
