# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/HTakafouyan/dnsprobe/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/HTakafouyan/dnsprobe/releases/tag/v1.0.0
