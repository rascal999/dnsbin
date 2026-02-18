# dnsbin (v1.5)

`dnsbin` is a tool for exfiltrating and recovering data over a DNS side-channel by leveraging the Time-To-Live (TTL) values of cached DNS records. It treats a DNS resolver's cache as a shared bit-array, allowing communication between devices that can access the same DNS server without direct connectivity.

![dnsbin demo](demo.gif)

## Features
- **Side-Channel Communication**: Encode data in the presence or absence of DNS cache entries.
- **Protocol Specification**: Implements the DNS TTL Side-Channel Exfiltration Protocol (see `go/RFC.md`).
- **Integrity Protection**: Optional block-level CRC32 checksums for reliable data recovery.
- **Cross-Platform**: Includes both a Go implementation and a Bash proof-of-concept.

## Repository Structure
- `go/`: Main implementation in Go, including the protocol specification (`RFC.md`).
- `bash/`: Bash scripts for simple exfiltration tests.
- `demo.gif`: A visual demonstration of the tool in action.

## Getting Started
Refer to the `go/` directory for build instructions and detailed protocol information.

## Disclaimer
This tool is for educational and research purposes only. Ensure you have permission before testing against any DNS infrastructure you do not own.
