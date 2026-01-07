# RFC: DNS TTL Side-Channel Exfiltration Protocol (v1.6)

## 1. Introduction
This document specifies a protocol for exfiltrating data over a DNS side-channel by leveraging the Time-To-Live (TTL) values of cached DNS records. This method is designed to bypass traditional traffic inspection by encoding data in the *presence* of a cache entry rather than the content of the DNS response.

## 2. Protocol Overview
The protocol treats a DNS resolver's cache as a shared bit-array. 
- A bit value of `1` is represented by the presence of a cached record for a specific subdomain.
- A bit value of `0` is represented by the absence of a cached record.

## 3. Header Specification
Every transmission MUST begin with a 3-byte header.

### 3.1 Options Byte (1 Byte)
The first byte defines the protocol features for the current session.

| Bit(s) | Name | Description |
|---|---|---|
| 0-1 | Encoding | `00`: Standard TTL Bitstream (Current) `01-11`: Reserved |
| 2 | Integrity | `0`: No Integrity Check `1`: CRC32 Enabled (256-byte blocks) |
| 3-7 | Reserved | Reserved for future use (Encryption, Compression, etc.) |

### 3.2 Message Length (2 Bytes)
A `uint16` (Big-Endian) representing the total length of the message payload in bytes.
- Minimum: 0 bytes
- Maximum: 65,535 bytes

## 4. Transmission Mechanism

### 4.1 Subdomain Mapping
Each bit in the bitstream is mapped to a unique subdomain:
`{bit_position}.{uuid}.{domain}`

- `bit_position`: The global index of the bit in the stream (starting at 0).
- `uuid`: A unique 8-character session identifier.
- `domain`: The target domain controlled by the operator.

### 4.2 Sending (Exfiltration)
For every bit in the bitstream (Header + Payload + Optional Checksums):
1. If the bit is `1`, the sender triggers a DNS query for the corresponding subdomain.
2. If the bit is `0`, the sender performs no action.

### 4.3 Receiving (Recovery)
The receiver establishes a baseline TTL by querying `baseline.{uuid}.{domain}` and an end-marker TTL via `end.{uuid}.{domain}`.
For each bit position:
1. Query the subdomain.
2. If the returned TTL is less than or equal to the end-marker TTL, the bit is recovered as `1`.
3. Otherwise, the bit is recovered as `0`.

## 5. Integrity (Block-Level CRC32)
If Bit 2 of the Options Byte is set to `1`, the following integrity mechanism MUST be used:

### 5.1 Segmentation
The message payload is divided into segments of **256 bytes**.

### 5.2 Interleaved Checksums
For each 256-byte segment:
1. The sender exfiltrates the 256 bytes of data.
2. The sender immediately exfiltrates a 4-byte (32-bit) CRC32 checksum calculated for that specific segment.
3. The final segment, if less than 256 bytes, is followed by a CRC32 calculated for the remaining bytes.

### 5.3 Verification
The receiver MUST calculate the CRC32 for each recovered 256-byte segment and compare it to the recovered checksum bits. If a mismatch occurs, the segment MUST be marked as corrupt.

## 6. Control Markers
- `baseline.{uuid}.{domain}`: Used to establish the resolver's default TTL.
- `end.{uuid}.{domain}`: Triggered after all data is sent to establish a "fresh" cache entry for comparison.

## 7. Security Considerations
- **Visibility**: DNS queries are often logged. This protocol is detectable via frequency analysis of subdomains.
- **Reliability**: Cache eviction and network jitter can cause bit-flips. Block-level CRC32 is highly recommended for payloads exceeding 1KB.