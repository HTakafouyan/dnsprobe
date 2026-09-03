# dnsprobe

A Windows DNS diagnostic tool that lets you choose **which network interface and which source IP
address** a DNS query originates from.

`dnsprobe` speaks the DNS protocol itself. It builds and parses the packets, opens the socket,
binds it, and pins it to an interface. It never shells out to `nslookup.exe`, `Resolve-DnsName` or
`System.Net.Dns`.

**Requirements:** Windows 10 / 11 / Server 2016 or newer, x64. .NET 8 SDK to build; the published
binary can be self-contained and needs nothing installed on the machine that runs it. No
administrator rights required. The interface pinning and routing inspection are Windows-specific,
so this tool is Windows-only by design.

---

## Contents

1. [What the tool does](#1-what-the-tool-does)
2. [Why nslookup is not enough](#2-why-nslookup-is-not-enough)
3. [Build and install](#3-build-and-install)
4. [Recipes](#4-recipes)
5. [Usage and output](#5-usage-and-output)
6. [Interface and source IP selection](#6-interface-and-source-ip-selection)
7. [DNS server selection](#7-dns-server-selection)
8. [Transport, EDNS and record classes](#8-transport-edns-and-record-classes)
9. [Delegation trace](#9-delegation-trace)
10. [Routing, ARP and the part everyone gets wrong](#10-routing-arp-and-the-part-everyone-gets-wrong)
11. [Diagnosis, stages and observations](#11-diagnosis-stages-and-observations)
12. [Scripting: JSON, --short and exit codes](#12-scripting-json---short-and-exit-codes)
13. [Limitations](#13-limitations)
14. [Troubleshooting](#14-troubleshooting)
15. [Verifying with Wireshark](#15-verifying-with-wireshark)
16. [Security considerations](#16-security-considerations)
17. [Architecture](#17-architecture)
18. [Tests](#18-tests)
19. [Licence](#19-licence)

---

## 1. What the tool does

- Lists every network adapter with its index, addresses, gateways and configured DNS servers,
  classified as Ethernet, Wi-Fi, VPN, tunnel, Hyper-V, container/WSL or VM adapter.
- Sends a real DNS query (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, SRV, or any numeric type) over
  UDP or TCP, in class IN, CH or HS.
- Binds the socket to a source IP **and** pins it to an interface index with `IP_UNICAST_IF` /
  `IPV6_UNICAST_IF`.
- Inspects the real Windows routing table (`GetBestRoute2`, `GetBestInterfaceEx`) and the neighbour
  cache (`GetIpNetEntry2`), and warns when your selection disagrees with them.
- Runs the same query from **every** eligible interface, compares the results, and states what can
  be deduced from the comparison.
- Walks the delegation chain from the root servers down (`--trace`).
- Repeats a query and reports loss / min / max / average / jitter.
- Supports EDNS(0): payload size, the DNSSEC DO bit, NSID and Extended DNS Errors, with an
  automatic retry when a middlebox will not tolerate EDNS.
- Shows how far a failing query actually got, with the evidence behind each verdict.
- Emits JSON for monitoring scripts, or a single value for shell pipelines.
- Dumps the raw packets in hex.

## 2. Why `nslookup` is not enough

`nslookup` lets you choose the *server*, but gives you no control over the *client* side of the
socket:

| Question | `nslookup` | `dnsprobe` |
| --- | --- | --- |
| Which DNS server do I ask? | yes | yes |
| Which local IP is the query sent **from**? | no | `--source-ip` |
| Which adapter does the packet leave through? | no | `--interface` / `--interface-index` |
| Does the routing table agree with my choice? | no | `--route-check` |
| Is the gateway even answering at layer 2? | no | shown in the stage list |
| Which of my NICs can actually reach this resolver? | no | `--compare` |
| Where does the delegation chain break? | no | `--trace` |
| Is something rewriting my DNS answers? | no | flag and EDNS checks |
| Can a script consume the result? | poorly | `--json`, `--short`, exit codes |

On a box with a LAN NIC, a VPN tunnel, a Hyper-V switch and Wi-Fi all up at once, "the DNS server
does not answer" is almost never a DNS problem - it is a *path* problem. `nslookup` cannot show you
the path. That is the gap this tool fills.

## 3. Build and install

```powershell
git clone https://github.com/HTakafouyan/dnsprobe.git
cd dnsprobe

dotnet build src\DnsProbe\DnsProbe.csproj -c Release

# self-contained single file, nothing to install on the target machine
dotnet publish src\DnsProbe\DnsProbe.csproj -c Release -r win-x64 `
  -p:PublishSingleFile=true -p:SelfContained=true -o publish
```

Or just run **`build.cmd`**, which does both and falls back to a framework-dependent build if the
self-contained one is not possible.

The executable is named `dnsprobe.exe`. The projects target `net8.0`; with the .NET 10 SDK change
`<TargetFramework>` in both `.csproj` files to `net10.0`, no source changes needed.

The application itself has **no third-party dependencies**. Only the test project needs packages
(xunit), so `dotnet build` on the application works on a machine with no NuGet access;
`dotnet test` does not.

**Administrator rights are not required.** Binding a source address, setting `IP_UNICAST_IF` and
sending UDP/TCP to port 53 are all unprivileged operations.

## 4. Recipes

The fastest way to see what the tool is for. Each of these answers a question that is awkward or
impossible with the built-in Windows tools.

**1. Which of my adapters can actually reach this resolver?**

```powershell
dnsprobe intranet.example.com --server 10.10.10.53 --compare
```

One row per interface, and a `Diagnosis` block stating what follows from the results.

**2. Is this a network problem or a DNS problem?**

```powershell
dnsprobe example.com --server 10.10.10.53 --verbose
```

If it fails, the `Probe Stages` block shows exactly how far the query got: routing, the gateway's
ARP entry, the socket, the send, the reply.

**3. Force the query out of the VPN tunnel, not the Wi-Fi.**

```powershell
dnsprobe intranet.example.com --interface "Ethernet 4" --system-dns --verbose
```

**4. Prove that source binding is not interface selection.**

```powershell
dnsprobe example.com --interface "Wi-Fi" --server 8.8.8.8 --route-check --verbose
dnsprobe example.com --interface "Wi-Fi" --server 8.8.8.8 --route-check --verbose --no-unicast-if
```

Same source address, different mechanism. On a machine whose routing table prefers another adapter
these two produce different results, and different Windows errors.

**5. Is the link flaky, or is the server slow?**

```powershell
dnsprobe example.com --server 10.10.10.53 --count 20 --interval 500
```

Loss, min, max, average and jitter. Jitter separates "the server is slow" from "the path is bad".

**6. Where does this domain's delegation break?**

```powershell
dnsprobe broken.example.com --trace
```

Root → TLD → the zone's own servers, one line per hop, stopping where the chain does.

**7. Is something intercepting my DNS?**

```powershell
dnsprobe example.com --server 8.8.8.8 --verbose
dnsprobe example.com --trace
dnsprobe example.com --server 8.8.8.8 --count 10 --interval 2000
```

Three independent signals: an EDNS query answered without an OPT record, a root server that answers
questions it should only refer, and a TTL that never counts down.

**8. Which anycast backend answered me?**

```powershell
dnsprobe example.com --server 9.9.9.9 --nsid --verbose
```

**9. Why did this resolver return SERVFAIL?**

```powershell
dnsprobe dnssec-failed.example.com --server 10.10.10.53 --dnssec --verbose
```

Extended DNS Errors turn a bare `SERVFAIL` into "signature expired" or "no reachable authority".

**10. Ask a server to identify itself.**

```powershell
dnsprobe version.bind --type TXT --class CH --server 10.10.10.53 --no-recurse
```

Class `CH`, not `IN`. In class `IN` every server returns NXDOMAIN for that name.

**11. Get just the IP address, for a script.**

```powershell
$ip = dnsprobe example.com --server 10.10.10.53 --short
```

**12. Monitor a resolver from a scheduled task.**

```powershell
dnsprobe example.com --server 10.10.10.53 --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { Send-Alert }
```

**13. Reverse-lookup an address on the internal DNS.**

```powershell
dnsprobe 10.10.10.90 --server 10.10.10.53
```

The `--type PTR` and the `in-addr.arpa` name are implied.

**14. Check the mail records of a domain from two different vantage points.**

```powershell
dnsprobe example.com --type MX --server 10.10.10.53
dnsprobe example.com --type MX --server 9.9.9.9
```

A split-horizon zone answers these differently, which is usually the explanation for "mail works
inside but not outside".

**15. Retrieve a large TXT record set.**

```powershell
dnsprobe example.com --type TXT --server 9.9.9.9 --tcp-fallback --verbose
```

EDNS usually keeps it on UDP; if the answer is still truncated the query is repeated over TCP and
says so.

**16. See the actual bytes on both directions.**

```powershell
dnsprobe example.com --server 10.10.10.53 --debug
```

**17. Find out what a fresh machine is even configured with.**

```powershell
dnsprobe --interfaces --all
```

**18. Let the tool walk you through it.**

```powershell
dnsprobe
```

A menu-driven session that prints the equivalent command line before it runs.

## 5. Usage and output

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

2 loopback/inactive interface(s) hidden. Use --all to show them.
```

VPN and tunnel adapters are highlighted; Hyper-V, Docker/WSL and VM adapters are dimmed, so the
physical paths stand out at a glance.

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
EDNS            : version 0, UDP payload 1232
Retries         : 1
Interface Pin   : IP_UNICAST_IF

Local endpoint  : 10.10.10.20:53142
Remote endpoint : 10.10.10.53:53
Response received.
Round Trip Time : 7.10 ms
Transaction ID  : 0xA31F
Response Code   : NOERROR
Transport       : UDP
Flags           : qr aa rd ra
  Authoritative : yes
  Truncated     : no
  Recursion Des.: yes
  Recursion Av. : yes
Counts          : 1 question, 1 answer, 0 authority, 1 additional
EDNS Response   : version 0, UDP payload 4000

Answer:
  example.com. -> 10.10.10.90
    Type        : A
    TTL         : 3600 s

Notes:
  - IP_UNICAST_IF was set to interface index 15 (network byte order).

RESULT: OK - 10.10.10.90 in 7.10 ms via Ethernet 2 (10.10.10.20)
```

### Comparing every interface

```
> dnsprobe intranet.example.com --server 10.10.10.53 --compare

Interface   Source IP       Result         RTT
--------------------------------------------------
Ethernet 2  10.10.10.20     SUCCESS        16.1 ms
Wi-Fi       192.168.1.20    NET-UNREACH    -

Ethernet 2: 10.10.10.90
Wi-Fi: Network is unreachable: Windows has no route from the selected source address to 10.10.10.53.

Diagnosis
----------------------------------------
  10.10.10.53 is reachable: Ethernet 2 got an answer. The failure on Wi-Fi is therefore specific
  to that path, not to the DNS server.
  Wi-Fi had no route to the server, so nothing was ever sent. Run with --route-check on that
  interface to see the routing decision.

RESULT: PARTIAL - 1 of 2 tested interface(s) reached 10.10.10.53: Ethernet 2
```

Column widths are computed from the data, so long Windows adapter names are not truncated.

Host-internal virtual switches - Hyper-V, WSL, Docker, VMware, VirtualBox - are skipped, and the
tool says how many. They exist to connect the host to its guests and have no route to an external
resolver by design, so testing them produces a guaranteed failure that carries no information.
`--compare-all` includes them.

### Repeated queries

```
> dnsprobe example.com --server 10.10.10.53 --count 5

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

RESULT: PARTIAL LOSS - 4/5 received, avg 8.00 ms via routing table
```

### Colour and the closing summary

Output is colour coded when the console supports it: green for successful results, red for definite
failures, yellow for answers that arrived but deserve a second look, and cyan for the values you
selected yourself. Round trip times are green below 50 ms, yellow below 200 ms and red above that.

Every run ends with a single `RESULT:` line:

```
RESULT: OK - 10.10.10.90 in 14.8 ms via Ethernet 2 (10.10.10.20)
RESULT: NODATA - no MX record for example.com (13.4 ms)
RESULT: TIMEOUT - no usable answer from 10.10.10.53 via Ethernet (192.168.1.20)
RESULT: IF-UNREACH - no usable answer from 8.8.8.8 via Wi-Fi (192.168.1.20)
RESULT: OK - 10/10 received, avg 46.5 ms via Ethernet 2 (10.10.10.20)
RESULT: PARTIAL - 1 of 2 tested interface(s) reached 10.10.10.53, 1 skipped: Ethernet 2
```

Colour is never the only carrier of meaning - the same information is in the text - so nothing is
lost when it is switched off. It is disabled automatically when the output is redirected, when
`NO_COLOR` is set, or when the console does not support ANSI escapes. `--no-color` forces it off.

### Interactive mode

Running `dnsprobe` with no arguments asks what you want to do first, then only the questions that
task needs:

```
dnsprobe - what would you like to do?

  [1] Look up a name
  [2] Compare every interface against one DNS server
  [3] Test reliability (repeat a query and show statistics)
  [4] Look up a name and show the routing path
  [5] List network interfaces
  [6] Reverse lookup an IP address
```

Before running, it prints the command line that would do the same thing:

```
Equivalent command:
  dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --verbose
```

That line is the point of the mode: after a few sessions you no longer need it.

## 6. Interface and source IP selection

```powershell
dnsprobe example.com --interface "Ethernet 2"
dnsprobe example.com --interface-index 15
dnsprobe example.com --source-ip 10.10.10.20
```

`--interface` matches, in this order: the exact connection name, the exact adapter description, the
adapter GUID, then a unique substring. An ambiguous match is an error, never a guess:

```
ERROR: "Ethernet" is ambiguous - it matches "Ethernet 4" (index 15), "Ethernet 3" (index 17).
Use the exact name or --interface-index.
```

If you give only `--source-ip`, the owning adapter is looked up for you. If you give both, they are
cross-checked:

```
ERROR: Source IP 192.168.1.20 does not belong to interface "Ethernet 2".
It is configured on "Ethernet".
```

The chosen adapter must be operational; `--allow-down` overrides that. If an interface has several
addresses of the chosen family, the first non-link-local one is used and you are told, so you can
override with `--source-ip`.

## 7. DNS server selection

```powershell
dnsprobe example.com --server 10.10.10.53
dnsprobe example.com --server 10.10.10.53#5353
dnsprobe example.com --server 2001:4860:4860::8888
dnsprobe example.com --server "[2001:db8::1]:5353"
dnsprobe example.com --interface "Ethernet 2" --system-dns
```

The server must be an IP address. `dnsprobe` deliberately refuses to resolve a server *name*,
because doing so would require the very resolver you are trying to diagnose.

With `--system-dns`, or with no `--server` at all, the tool reports where the server came from:

```
DNS Server      : 10.10.10.53
Server Source   : DNS configuration of Ethernet 2
```

**If you selected an interface, only that interface's DNS servers are considered.** If it has none
for the chosen family you get an error rather than a silent fallback to another adapter's resolver -
quietly querying `192.168.1.1` while you asked for `Ethernet 2` would invalidate the whole test.

## 8. Transport, EDNS and record classes

### UDP and TCP

```powershell
dnsprobe example.com --protocol udp        # default
dnsprobe example.com --tcp                 # shorthand for --protocol tcp
dnsprobe example.com --tcp-fallback        # retry over TCP if TC=1
```

DNS over TCP uses the two-byte big-endian length prefix from RFC 1035 §4.2.2. The reader loops
until exactly that many bytes have arrived, and a premature close is reported as such.

The UDP socket is intentionally left unconnected, so a response from an unexpected sender is
visible to the tool and reported rather than silently dropped by the stack.

### IPv4 and IPv6

`--ipv4` / `--ipv6` force a family. Otherwise it is inferred, in order, from `--source-ip`, then
`--server`, then defaults to IPv4. Families are never mixed: a v6 socket is created with
`DualMode = false`, and any impossible v4/v6 combination is rejected up front with an explanation.

### EDNS(0)

EDNS(0) (RFC 6891) is on by default. It attaches a small OPT pseudo-record advertising how large a
UDP answer this client accepts, which lifts the 512 byte limit plain RFC 1035 DNS imposes.

```powershell
dnsprobe example.com --server 9.9.9.9 --verbose      # EDNS on, 1232 byte payload
dnsprobe example.com --server 9.9.9.9 --edns 4096    # advertise a larger buffer
dnsprobe example.com --server 9.9.9.9 --no-edns      # plain RFC 1035 query
dnsprobe example.com --server 9.9.9.9 --dnssec       # set the DO bit
dnsprobe example.com --server 9.9.9.9 --nsid         # ask the server to identify itself
```

The default 1232 bytes is not arbitrary: it keeps the response below the smallest MTU IPv6
guarantees, so the answer never has to be fragmented. Fragmented DNS is both a reliability and a
security problem, so bigger is not better. The accepted range is 512 to 4096.

What the server sends back is reported too:

```
EDNS            : version 0, UDP payload 1232, DO
EDNS Response   : version 0, UDP payload 4000
Server NSID     : dns-node-7
Extended Error  : 6 (DNSSEC Bogus) - signature verification failed
```

* **Extended DNS Errors** (RFC 8914) turn a bare `SERVFAIL` into an actual explanation. They are
  shown even without `--verbose`, because they are usually the whole answer to "why did this fail".
* **NSID** (RFC 5001) tells you *which* server answered. Behind an anycast address that is often
  the only way to tell one backend from another.
* **The extended RCODE** adds 8 bits to the 4 bit header code, which is how `BADVERS` and friends
  can be reported at all.

Some firewalls and older resolvers mishandle queries carrying an OPT record. When an EDNS query
times out or comes back `FORMERR`/`NOTIMP`, dnsprobe repeats it without EDNS and says what it found:

```
The query failed while carrying an EDNS(0) OPT record, but the same query without EDNS succeeded.
Something on this path does not tolerate EDNS - a firewall, a middlebox, or an old resolver.
Use --no-edns against this server.
```

### Record classes

`--class` selects the query class. It defaults to `IN` and almost always should be, with one
practical exception: `version.bind` and `id.server` are only meaningful in class `CH`, and asking
for them in class `IN` returns NXDOMAIN from every server.

```powershell
dnsprobe version.bind --type TXT --class CH --server 10.10.10.53 --no-recurse
dnsprobe id.server --type TXT --class CH --server 10.10.10.53 --no-recurse
```

## 9. Delegation trace

`--trace` walks the chain from the root servers down to the authoritative server, asking each level
itself with recursion disabled - the way a resolver does it:

```
> dnsprobe example.com --trace

Delegation trace for example.com (A)
----------------------------------------
  .            a.root-servers.net  (198.41.0.4)      31.2 ms  -> com (13 name server(s))
  com          e.gtld-servers.net  (192.12.94.30)    44.8 ms  -> example.com (2 name server(s))
  example.com  a.iana-servers.net  (199.43.135.53)   58.1 ms  -> ANSWER

  93.184.216.34  (A, TTL 86400s)
  3 step(s), 134.1 ms total, authoritative
```

One line per hop, on purpose. `dig +trace` prints every NS record of every level, which runs to
hundreds of lines and buries the single fact the reader came for. Add `--verbose` to list the name
servers at each level when you do want them.

When the chain breaks, the last line says where and why:

```
  The chain stops at zone ".": none of the 3 name server(s) tried would answer.
```

### Flag checks

Header flags are checked against what each step should have produced, and shown only when they
depart from it:

```
  .   a.root-servers.net  (198.41.0.4)   41.2 ms  -> ANSWER
      FLAGS   qr ra
              unexpected: aa absent (the answer did not come from a server for this zone)
              unexpected: ra set on a root server, which never performs recursion
```

A referral should carry `qr` alone; an authoritative answer should carry `qr aa`. Root and TLD
servers never set `ra`, because they do not perform recursion - so `ra` at those levels means
something other than that server replied. Normal flags are noise on a healthy chain, so they only
appear under `--verbose`.

### Design notes

Root server addresses are hard-coded, because asking a resolver where the root servers are would
defeat the point of starting from the root. A referral with no glue records stops the walk and says
so rather than quietly falling back to a resolver.

Each level is asked of one server, because every server for a zone holds the same data and thirteen
identical referrals would bury the useful line. If that server does not answer, the next one is
tried, and the dead one is shown in red rather than hidden:

```
  .   b.root-servers.net  (170.247.170.2)   38.4 ms  -> com (13 name server(s))
      FAILED  no answer from a.root-servers.net (no reply)
```

`--trace-servers <n>` sets how many to try per level, from 1 to 13. The default is 3: enough to
survive one dead server, few enough that a fully blocked path reports something in a few seconds
instead of spending thirteen timeouts on the root alone.

Three things make the trace worth having:

* **It localises a resolution failure.** A name that will not resolve fails at the root, at the
  TLD, at the registrar's delegation, or at the zone's own servers - four different people to talk
  to. The trace says which.
* **It respects the interface selection.** `--trace --interface "Ethernet 2"` walks the whole chain
  from that one adapter, which no other tool will do.
* **It exposes interception.** A trace talks to root and TLD servers directly with recursion off.
  Anything that answers those queries on their behalf is not a healthy path.

## 10. Routing, ARP and the part everyone gets wrong

This is the core of the tool, so it is worth being precise.

### Four different things

1. **Source IP selection** - which address goes into the source field of the IP header.
2. **Interface selection** - which adapter the frame is actually handed to.
3. **The Windows routing decision** - which route entry Windows picks, by longest prefix then metric.
4. **Next-hop resolution** - whether the gateway actually answers at layer 2.

They are not the same thing, and controlling one does not control the others.

### What `Socket.Bind()` really does

`Socket.Bind(new IPEndPoint(10.10.10.20, 0))` fixes the **source address** of the socket. It does
**not** tell the TCP/IP stack which interface to use. The route lookup still happens against the
full routing table, so if the best route for `10.10.10.53` points out of `Ethernet`, the packet can
leave through `Ethernet` carrying `10.10.10.20` as its source. That is exactly the situation that
produces "I bound to the right IP and still got no answer".

So this claim, which you will see in a lot of sample code, is **false**:

> "Binding the source IP guarantees the packet will leave through this interface."

`dnsprobe` does not make that claim anywhere.

### What actually pins the interface

Windows exposes a socket option for it:

* IPv4: `IP_UNICAST_IF` (option 31, level `IPPROTO_IP`)
* IPv6: `IPV6_UNICAST_IF` (option 31, level `IPPROTO_IPV6`)

Setting it makes the stack perform the route lookup **constrained to that interface**, which is the
supported user-mode way of forcing outbound unicast traffic onto a specific adapter.

There is a byte-order trap that silently breaks naive implementations:

| Option | Byte order of the interface index |
| --- | --- |
| `IP_UNICAST_IF` (IPv4) | **network** byte order |
| `IPV6_UNICAST_IF` (IPv6) | **host** byte order |

Passing the wrong one does not fail - it pins the socket to a nonsense interface index.

Windows also reports the two situations differently, which the tool preserves: a pinned socket with
no route fails with `WSAEINVAL` and is reported as `IF-UNREACH`, while an unpinned one fails with a
routing error and is reported as `NET-UNREACH`. Running the same query with and without
`--no-unicast-if` and getting two different errors is the practical proof that these mechanisms are
not the same.

### Route check

```
> dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --route-check

Route Check
----------------------------------------
Destination : 10.10.10.53
Source      : 10.10.10.20
Interface   : Ethernet 2
Gateway     : On-link
Route Egress: Ethernet 2 (index 15, metric 271)
Route Source: 10.10.10.20 (what Windows would pick without an explicit bind)
```

Green when the routing table agrees with your selection, yellow when it does not, with a warning
explaining the disagreement. Routing data comes from `GetBestRoute2` and `GetBestInterfaceEx`.
Nothing is invented: if the API fails the tool prints the Win32 error. Codes 1231/1232 are
translated, because "no route to the destination" is a diagnostic answer, not an API malfunction.

### The neighbour cache

A route can exist on paper while the gateway never answers at layer 2. When that happens every
packet is dropped locally, and the result is indistinguishable from a filtered path - unless you
look. `dnsprobe` reads the Windows neighbour cache (the ARP table for IPv4, neighbour discovery for
IPv6) for the next hop:

```
  Next hop     OK       neighbour cache: reachable (00-1C-B1-FA-4C-00)
  Next hop     FAILED   neighbour cache: not in cache
```

## 11. Diagnosis, stages and observations

Three separate blocks, with three different levels of confidence. Keeping them apart is deliberate.

### Probe stages - what was measured

Shown when a query fails, or with `--verbose`:

```
Probe Stages
----------------------------------------
  Interface    OK       Ethernet 2, index 15, pinned with IP_UNICAST_IF
  Route        OK       GetBestRoute2: index 15 via 10.10.10.1, metric 281
  Next hop     FAILED   neighbour cache: not in cache
  Socket       OK       bound to 10.10.10.20:53142
  Send         OK       28 bytes accepted by the stack (not proof that a frame reached the wire)
  Receive      FAILED   DNS request timed out after 2000 ms.
```

The evidence column is not decoration. Each line says how the verdict was reached, because a bare
`OK` invites the reader to believe more was verified than actually was.

The **Send** stage is deliberately not called "packet transmitted". A successful `send()` means the
stack accepted the datagram, not that a frame left the adapter. Only a capture can confirm that,
and claiming otherwise would contradict the distinction this whole tool is built on.

There is no "likely causes" list. Listing four possibilities is not a diagnosis, and a tool that
presents guesses in the shape of conclusions is worse than one that stays quiet.

### Diagnosis - what follows from the measurements

With `--compare`, results from several paths become a deduction rather than a guess:

```
Diagnosis
----------------------------------------
  10.10.10.53 is reachable: Ethernet 2 got an answer. The failure on Wi-Fi is therefore specific
  to that path, not to the DNS server.
  Wi-Fi had no route to the server, so nothing was ever sent.
```

Every sentence follows from something measured. If one interface got an answer, the server is
demonstrably up; if another got `NET-UNREACH`, nothing was ever sent. Those are deductions, not
hypotheses, which is the only reason this block exists.

### Observations - what merits a second look

Things visible in a response that are not errors:

```
Observations
----------------------------------------
  - An EDNS(0) OPT record was sent but the response carried none. A server that supports EDNS is
    required to echo one, so either this server is old, or something between you and it rewrote
    the response. Compare with --tcp and with a different server.
```

Single-response checks: an EDNS query answered without an OPT record, an answer truncated despite a
large advertised payload, a server advertising a UDP payload above 1500 bytes (which will be
fragmented on most links), and recursion requested but unavailable.

With `--count` there is one more, and it is the most useful: whether the TTL counts down between
queries. A caching resolver decrements it, so a TTL that never moves suggests the answer is being
generated rather than served from a real cache.

That check is skipped entirely when any response has `aa=1`. An authoritative server reads the TTL
straight out of its zone file and never counts it down, so applying the check there would produce a
false alarm on every correctly configured internal DNS server. It also needs a window of at least
five seconds; below that it says so instead of guessing:

```powershell
dnsprobe example.com --server 9.9.9.9 --count 10 --interval 2000
```

Every observation is a heuristic. The wording says "suggests" rather than "is", on purpose - a
diagnostic tool that overstates its conclusions is worse than one that stays quiet, because people
act on what it says.

## 12. Scripting: JSON, `--short` and exit codes

### `--short`

Answer values only, one per line, nothing else - the equivalent of dig's `+short`:

```powershell
> dnsprobe example.com --server 10.10.10.53 --short
10.10.10.90
```

### `--json`

One JSON document instead of all human readable output. Nothing else is written to stdout and the
exit code is unchanged.

```powershell
dnsprobe example.com --server 10.10.10.53 --json
dnsprobe example.com --server 10.10.10.53 --count 10 --json
dnsprobe example.com --server 10.10.10.53 --compare --json
dnsprobe example.com --trace --json
dnsprobe --interfaces --json
```

Every document carries `tool`, `version`, `timestamp`, `status` and `exitCode`. Consumers should
branch on `status` and `exitCode` rather than parsing prose fields. Failures, including usage
errors, are reported as JSON too:

```json
{
  "tool": "dnsprobe",
  "status": "error",
  "exitCode": 3,
  "error": "Source IP 192.168.1.20 does not belong to interface \"Ethernet 2\"."
}
```

A successful query adds `query`, `probe`, `fallbacks`, `response` and `observations`; `--count`
replaces `response` with `statistics`; `--compare` replaces it with `results` plus `diagnosis`,
`interfacesTested` and `interfacesSkipped`; `--trace` adds a `trace` object with one entry per hop,
each carrying its flags and any `flagAnomalies`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | response received, `RCODE = NOERROR` |
| 1 | response received with a non-zero RCODE (SERVFAIL, NXDOMAIN, REFUSED, …) |
| 2 | no usable response (timeout, unreachable, malformed) |
| 3 | invalid command line, or an impossible interface/source selection |

## 13. Limitations

* **Verification is your job, and Wireshark is the referee.** `dnsprobe` reports the socket's local
  endpoint and the options it set; it cannot observe the wire. See §15.
* Pinning the interface does not create connectivity. If that path cannot reach the resolver you
  get a timeout - which is usually the answer you were looking for.
* Policy-based routing, third-party WFP/LSP filter drivers, VPN clients that redirect traffic in
  the kernel, and NRPT rules can all override what the socket asked for. Such drivers are outside
  anything a user-mode tool can inspect.
* EDNS(0) covers payload size, the DO bit, NSID and Extended DNS Errors. Other options (cookies,
  client subnet, padding) are preserved but not decoded.
* DNSSEC records can be requested with `--dnssec` and are displayed, but signatures are **not**
  validated - that is a resolver's job, not a probe's.
* No DoT / DoH / DoQ, no zone transfers, no dynamic updates.
* `--trace` follows one server per level and stops at a referral with no glue rather than falling
  back to a resolver.
* `--compare` sends one query per interface sequentially, so it is not a load test, and a slow
  interface delays the ones after it.
* Interface classification (VPN / Hyper-V / Docker / WSL) is a keyword heuristic. Windows does not
  expose "this is a VPN adapter" as a first-class property.
* The routing and neighbour structures are read at fixed field offsets that are correct for
  x86/x64/ARM64 Windows; a future change to `MIB_IPFORWARD_ROW2` or `MIB_IPNET_ROW2` would require
  updating `NativeMethods`.

## 14. Troubleshooting

| Symptom | Meaning |
| --- | --- |
| `TIMEOUT` | The query left the stack and nothing came back. Filtering, an ACL, or a reply that took a different route home. Try `--compare`. |
| `PORT-UNREACH` | ICMP port unreachable: the host exists but nothing is listening on that port. A socket-level result, not a DNS one. |
| `NET-UNREACH` | No route from the bound source address. Run with `--route-check`. |
| `IF-UNREACH` | The interface you pinned has no route to the server. Windows reports `WSAEINVAL` because `IP_UNICAST_IF` forbids falling back. Re-run with `--no-unicast-if` to see what routing would have done. |
| `Next hop FAILED` in the stage list | The gateway is not answering ARP / neighbour discovery. Packets are dropped locally, before the wire. |
| `REFUSED` | A real DNS server answered and declined. Almost always an ACL keyed to your source address - which is exactly what `--compare` diagnoses. |
| `SERVFAIL` | Server-side failure: broken forwarder, DNSSEC failure, unreachable upstream. Add `--dnssec` to see if an Extended DNS Error explains it. |
| `NODATA` | The name exists but has no record of that type. Not a network problem. |
| `Source IP … does not belong to interface …` | Exactly what it says. Check `--interfaces`. |
| `"X" is ambiguous` | Two adapters match that substring. Use the full name or `--interface-index`. |
| Response is truncated (`TC=1`) | Add `--tcp-fallback` or `--tcp`. |

`PORT-UNREACH` and `REFUSED` are deliberately different labels. `REFUSED` is the DNS RCODE: a real
server received the query and declined it. `PORT-UNREACH` happens one layer lower - the packet
reached the host but nothing was listening, so no DNS conversation took place at all. The fix
differs in each case, so the tool never uses one name for both.

## 15. Verifying with Wireshark

This is the only way to *prove* the packet left where you wanted it to.

Test bed:

```
NIC 1  "Ethernet"     192.168.1.20/24   gateway 192.168.1.1
NIC 2  "Ethernet 2"   10.10.10.20/24    gateway 10.10.10.1
DNS server           10.10.10.53
```

1. Start Wireshark and select the **`Ethernet 2`** adapter - the specific NIC, not "any".
2. Apply the display filter `udp.port == 53` (or `tcp.port == 53` for TCP tests).
3. Run:

   ```powershell
   dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53 --verbose
   ```

4. In the captured query packet confirm: **source IP = 10.10.10.20**, **destination IP =
   10.10.10.53**, **destination port 53**, the **source port** matching the `Local endpoint` line,
   and the **transaction ID** matching the one printed.

   A precise filter: `ip.src == 10.10.10.20 && ip.dst == 10.10.10.53 && udp.dstport == 53`

5. Capture on **`Ethernet`** at the same time and confirm **nothing** appears there. That negative
   result is the real proof of interface selection.
6. Repeat with `--no-unicast-if`. On a machine whose routing table prefers the other NIC you will
   see the difference between binding a source address and pinning an interface - the whole point
   of §10.

Without Wireshark:

```powershell
netsh trace start capture=yes tracefile=C:\temp\dns.etl
dnsprobe example.com --interface "Ethernet 2" --server 10.10.10.53
netsh trace stop
```

## 16. Security considerations

DNS responses are unauthenticated data from the network and are treated as hostile:

* Every read is bounds-checked before it happens; `RDLENGTH` is validated against the remaining
  buffer before any RDATA is touched.
* Name decoding is **iterative**, not recursive - no stack overflow path exists.
* A compression pointer must point **strictly backwards**. That single rule makes pointer loops
  impossible; a jump counter and a 255-byte total-length cap are layered on top.
* The two reserved label-type bit patterns are rejected rather than ignored.
* The record cursor always advances by `RDLENGTH`, so a lying RDATA cannot desynchronise the
  parser. A single undecodable record degrades to a raw record plus a warning.
* EDNS option lists are length-checked the same way; a truncated or lying option is reported and
  the rest ignored.
* Transaction IDs come from `RandomNumberGenerator` and the source port is a random ephemeral port.
  Responses with the wrong ID, the wrong sender endpoint, or a length below 12 bytes are discarded
  and counted.
* Names and TXT strings are escaped (`\ddd`) before display, so a hostile response cannot inject
  control sequences into your terminal.
* No `unsafe` code anywhere. Native buffers are handled through `Marshal` with explicit sizes and
  are always freed in a `finally`.
* The tool only ever *sends* queries; it never opens a listening socket.
* A fuzz-style test feeds 500 random byte arrays to the parser and asserts that nothing but
  `DnsProtocolException` escapes.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and what is in scope.

## 17. Architecture

```
dnsprobe/
├── DnsProbe.sln
├── build.cmd
├── src/DnsProbe/
│   ├── Program.cs                     entry point, top-level error handling
│   ├── ProbeRunner.cs                 orchestration + exit codes
│   ├── Cli/
│   │   ├── ProbeOptions.cs            the validated command line
│   │   ├── CommandLineParser.cs       parsing + combination validation
│   │   ├── HelpText.cs
│   │   └── InteractiveSession.cs      task-oriented zero-argument mode
│   ├── Network/
│   │   ├── InterfaceInfo.cs           adapter snapshot (plain data)
│   │   ├── NetworkInterfaceProvider.cs  enumeration + classification
│   │   ├── InterfaceSelector.cs       name/index/source-IP resolution
│   │   ├── SocketFactory.cs           Bind() + IP_UNICAST_IF / IPV6_UNICAST_IF
│   │   ├── RouteInspector.cs          GetBestRoute2 / GetBestInterfaceEx / GetIpNetEntry2
│   │   ├── NeighbourInfo.cs           ARP / neighbour discovery result model
│   │   └── NativeMethods.cs           P/Invoke, no unsafe
│   ├── Dns/
│   │   ├── DnsEnums.cs, DnsMessage.cs, DnsRecord.cs
│   │   ├── DnsName.cs                 safe encode/decode
│   │   ├── DnsPacketBuilder.cs        query construction, OPT record, TCP framing
│   │   ├── DnsPacketParser.cs         defensive response decoding
│   │   ├── EdnsInfo.cs                EDNS(0) options, NSID, Extended DNS Errors
│   │   ├── DnsQuery.cs                request/result model
│   │   ├── DnsClient.cs               UDP/TCP transport, retries, TCP + EDNS fallback
│   │   └── DnsTracer.cs               delegation chain walk from the root servers
│   └── Diagnostics/
│       ├── DiagnosticReporter.cs      all console output
│       ├── ConsoleTheme.cs            ANSI colour policy and detection
│       ├── ProbeStages.cs             how far the query got, with evidence
│       ├── ComparisonDiagnosis.cs     deductions across interfaces
│       ├── Observations.cs            single-response and over-time heuristics
│       ├── TraceFlagCheck.cs          expected vs actual header flags per trace step
│       ├── InterfaceComparer.cs       --compare
│       ├── QueryStatistics.cs
│       ├── JsonOutput.cs              --json
│       └── HexDump.cs                 --debug
└── tests/DnsProbe.Tests/
    ├── PacketWriter.cs                synthetic packet builder
    ├── DnsPacketBuilderTests.cs
    ├── DnsPacketParserTests.cs
    ├── DnsNameTests.cs
    ├── EdnsTests.cs
    ├── InterfaceSelectorTests.cs
    └── CommandLineParserTests.cs
```

Design rules: DNS parsing knows nothing about sockets; the network layer knows nothing about the
console; all output lives in `DiagnosticReporter`; interface selection is pure logic behind
`INetworkInterfaceProvider`, which is why it can be unit-tested against a synthetic five-NIC
machine; expected failures are return values (`ParseResult`, `InterfaceSelectionResult`,
`DnsQueryAttempt`) carrying a human readable explanation, not exceptions.

## 18. Tests

```powershell
dotnet test
```

Covered: query construction for A/AAAA/MX/PTR/NS/SOA, the OPT record with payload size, the DO bit
and NSID, TCP framing, name encoding including non-ASCII, oversized and empty labels; response
parsing for single and multiple answers, CNAME chains with compression, MX/TXT/SOA/PTR RDATA, every
response code, the truncated flag, short messages, lying `RDLENGTH`, forward and self-referencing
and mutual compression pointers, reserved label types, unknown record types, EDNS option lists
including truncated and lying lengths, extended RCODEs, and a 500-iteration random-input fuzz test;
interface lookup by name, exact-over-partial matching, lookup by index, name/index conflicts,
source-IP ownership validation, adapters without IPv4, down adapters, family inference and
mismatch; and the full CLI surface including every invalid combination.

Integration testing against real hardware is described in §15 and cannot be automated here - it
needs two NICs and a packet capture.

## 19. Licence

MIT. See [LICENSE](LICENSE).
