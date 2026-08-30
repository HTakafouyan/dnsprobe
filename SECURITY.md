# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |

Only the latest release receives fixes.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private reporting instead: go to the **Security** tab of this repository and choose
**Report a vulnerability**. That opens a private channel visible only to the maintainer.

Please include:

* what the problem is and what an attacker could achieve,
* the steps or the input needed to reproduce it,
* the version of dnsprobe and the Windows build you tested on,
* a packet capture or hex dump if the issue involves a malformed DNS response.

You can expect an acknowledgement within about a week. This is a small project maintained in spare
time, so please be patient with the timeline for a fix.

## Scope

dnsprobe parses DNS responses that come from the network, which is untrusted input by definition.
The following are in scope and are taken seriously:

* any input that makes the parser crash, hang, loop, or consume unbounded memory,
* compression pointer handling, `RDLENGTH` handling, or any out-of-bounds read,
* terminal escape sequences or control characters reaching the console through a response,
* the socket binding or interface pinning behaving differently from what the output reports.

The following are **not** vulnerabilities in this tool:

* a DNS server or a network path returning wrong or manipulated answers - detecting that is what
  the tool is for, and it reports what it observes,
* the absence of DNSSEC validation. `--dnssec` requests the records and displays them; it does not
  verify signatures, and the README says so,
* Windows SmartScreen warnings on the published binary, which is not code-signed.

## Design notes relevant to security

Responses are treated as hostile input throughout: every read is bounds-checked before it happens,
compression pointers may only jump backwards, name decoding is iterative rather than recursive,
the record cursor always advances by `RDLENGTH` regardless of what an RDATA decoder consumed, and
non-printable bytes are escaped before display. Transaction IDs come from a cryptographic random
source and the responder's endpoint and transaction ID are validated before a response is accepted.
There is no `unsafe` code in the project.
