# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.1.0] - 2026-09-03

A diagnostics release. 1.0 could tell you that a query failed; this one tells you where it failed
and, where the evidence supports it, what that means.

### Added

- **`--trace`**: walks the delegation chain from the root servers down to the authoritative server,
  asking each level itself with recursion disabled. One line per hop, because `dig +trace` prints
  every NS record of every level and buries the fact the reader came for. Root server addresses are
  hard-coded, since asking a resolver where the root servers are would defeat the point of starting
  at the root. A referral with no glue stops the walk and says so rather than falling back to a
  resolver.
- **`--trace-servers <n>`**: how many name servers to try per level before giving up on it (1-13,
  default 3). If one does not answer the next is tried, and the dead server is reported rather than
  quietly stepped over.
- **Trace flag checks**: header flags are compared against what each step should have produced and
  shown only when they depart from it. A referral should carry `qr` alone and an authoritative
  answer `qr aa`; root and TLD servers never set `ra`, so `ra` at those levels means something
  other than that server replied.
- **`Probe Stages`**: a stage-by-stage account of how far a query got - interface, route, next hop,
  socket, send, receive, DNS answer - each with the evidence behind its verdict. Shown on failure
  and with `--verbose`.
- **Neighbour cache lookup** (`GetIpNetEntry2`): checks whether the next hop actually answers at
  layer 2. A route can exist on paper while the gateway never replies to ARP or neighbour
  discovery, in which case every packet is dropped locally - otherwise indistinguishable from a
  filtered path.
- **`Diagnosis`**: with `--compare`, states what follows from the results across interfaces. If one
  path got an answer the server is demonstrably up, so a failure elsewhere is demonstrably
  path-specific. Deductions only; there is deliberately no list of "likely causes".
- **`--short`**: answer values only, one per line, for shell pipelines.
- **`--class <class>`**: query class selection (IN, CS, CH, HS, ANY or numeric). `version.bind` and
  `id.server` are only meaningful in class CH; asking for them in class IN returns NXDOMAIN from
  every server, which is what this tool used to do.
- **`--compare-all`**: includes host-internal virtual switches in the comparison, which `--compare`
  now skips.
- **A task-oriented interactive mode**: asks what you want to do first, then only the questions
  that task needs, and prints the equivalent command line before running so the mode teaches
  itself out of a job.
- `flags`, `flagAnomalies`, `observations`, `diagnosis`, `fallbacks`, `interfacesSkipped` and a
  full `trace` object in the JSON output.

### Changed

- `--compare` skips Hyper-V, WSL, Docker, VMware and VirtualBox adapters and reports how many were
  skipped. Those adapters connect the host to its guests and have no route to an external resolver
  by design, so testing them produced a guaranteed failure that carried no information.
- Comparison table columns are sized from the data instead of a fixed width that truncated most
  Windows adapter names.
- The comparison summary says how many interfaces were *tested* and how many were skipped, rather
  than implying the machine has no other adapters.
- In `--trace` the header no longer prints a configured DNS server address, because trace mode does
  not use one.
- The `Observations` TTL check is skipped when any response is authoritative. An authoritative
  server serves the TTL from its zone file and never counts it down, so the check produced a false
  alarm on every correctly configured internal DNS server. It also now requires a five second
  window and says so when it has less.
- The misleading `Sending query...` line was removed; it was printed as part of the result, so on a
  failed query it appeared after the errors it supposedly preceded.
- Socket-level refusal is reported as `PORT-UNREACH` instead of `REFUSED`. `REFUSED` is the DNS
  RCODE - a real server declining the query - and using one name for both hid the difference
  between "nothing is listening" and "the server said no".
- Win32 errors 1231 and 1232 from `GetBestRoute2` are translated into "no route to the
  destination". They are a diagnostic answer, not an API malfunction, and were being presented as
  the latter.
- The project targets `net8.0` rather than `net8.0-windows`. Nothing in the tool uses a Windows
  desktop API, and the narrower target avoids pulling the WindowsDesktop and AspNetCore runtime
  packs into a self-contained publish.

### Fixed

- A `WSAEINVAL` on a pinned socket is reported as `IF-UNREACH` with an explanation, instead of a
  generic socket failure. It means the pinned interface has no route to the destination - Windows
  reports it this way because `IP_UNICAST_IF` forbids falling back to another interface.
- A TCP connect that hit the timeout crashed with an unhandled `ObjectDisposedException`: the
  runtime disposes the socket when an async connect is cancelled, and the local endpoint was read
  afterwards. Endpoint reads are now safe and the timeout is reported as a timeout.
- The EDNS fallback message was lost whenever a later retry became the final attempt. It is now
  reported from the overall result rather than from one attempt's notes.
- The OPT pseudo-record no longer appears in the additional section, where it was shown a second
  time as an undecodable raw record.
- Adapters described as "Fortinet …" are classified as VPN. The keyword list matched only
  "forticlient", so the actual adapter name was labelled as physical Ethernet.
- Parse errors printed the "run --help" hint twice.
- `Math.Min` calls in the parser were ambiguous between the `int` and `ushort` overloads and did
  not compile.

## [1.0.0] - 2026-08-30

First release.

### Added

- DNS protocol implemented from scratch: query construction, response parsing, name
  compression, and the RFC 1035 two-byte length prefix for TCP. The tool never shells out to
  `nslookup.exe`, `Resolve-DnsName` or `System.Net.Dns`.
- Record types decoded structurally: A, AAAA, CNAME, MX, NS, TXT, PTR, SOA and SRV. Unknown
  types are preserved and shown in RFC 3597 form rather than dropped.
- Interface selection by name (`--interface`) or index (`--interface-index`), and explicit
  source address selection (`--source-ip`), with cross-validation between them.
- Egress interface pinning with `IP_UNICAST_IF` / `IPV6_UNICAST_IF` in addition to
  `Socket.Bind()`, and `--no-unicast-if` to demonstrate the difference between the two.
- Adapter enumeration with classification (Ethernet, Wi-Fi, VPN, tunnel, loopback, Hyper-V,
  container, virtual machine).
- Routing table inspection through `GetBestRoute2` and `GetBestInterfaceEx` (`--route-check`),
  with warnings when the routing decision disagrees with the selected interface.
- `--compare`: runs the same query from every eligible interface and reports them side by side.
- `--count`: repeats a query and reports loss, minimum, maximum, average and jitter.
- UDP and TCP transports, with automatic TCP retry on a truncated answer (`--tcp-fallback`).
- IPv4 and IPv6 with no family mixing, and reverse-name generation for both.
- EDNS(0): UDP payload size negotiation, the DNSSEC DO bit (`--dnssec`), NSID (`--nsid`) and
  Extended DNS Errors, plus an automatic retry without EDNS when a middlebox rejects it.
- `--json`: a single JSON document instead of human readable output, for monitoring scripts.
- Colour-coded console output with automatic detection, `--no-color`, and `NO_COLOR` support.
- A closing `RESULT:` line summarising every run.
- An `Observations` section that flags responses which look rewritten in transit, servers
  advertising oversized UDP payloads, and TTLs that never count down.
- `--debug`: hex dumps of the transmitted and received packets.
- Interactive mode when run with no arguments.
- Exit codes for scripting: `0` NOERROR, `1` non-zero RCODE, `2` no usable response,
  `3` usage error.

### Security

- The response parser treats every byte as hostile: bounds checks before every read, compression
  pointers restricted to backward jumps, a jump counter, label and name length limits, and a
  record cursor that always advances by `RDLENGTH` regardless of what an RDATA decoder read.
- Name decoding is iterative rather than recursive, so there is no stack overflow path.
- Non-printable bytes in names and TXT strings are escaped before display.
- Cryptographically random transaction IDs, random ephemeral source ports, and validation of the
  responder's endpoint and transaction ID before a response is accepted.
- No `unsafe` code anywhere.

[Unreleased]: https://github.com/HTakafouyan/dnsprobe/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/HTakafouyan/dnsprobe/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/HTakafouyan/dnsprobe/releases/tag/v1.0.0
