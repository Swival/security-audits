# IPv6 segment decoding depended on host endianness

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/net/mod.rs:24`

## Summary
Guest-supplied IPv6 octets were deserialized by reinterpreting `[u8; 16]` as `[u16; 8]` and passing those values into `Ipv6Addr::new`. `Ipv6Addr::new` expects numeric 16-bit segments in network order, so this logic silently byte-swapped every segment on little-endian hosts. As a result, imported IPv6 addresses, CIDRs, and routes were corrupted before host-side networking operations executed.

## Provenance
- Verified finding reproduced from scanner output
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- IPv6 address bytes are read on a little-endian host

## Proof
On reproduction, the IPv6 octets for `2001:db8::1` were decoded by the vulnerable path as `120:b80d::100`, while `Ipv6Addr::from(octets)` correctly produced `2001:db8::1`.

Reachability is direct because guest-controlled WASM memory is deserialized through the affected readers in active syscall paths, including:
- `lib/wasix/src/syscalls/wasix/port_addr_add.rs:22`
- `lib/wasix/src/syscalls/wasix/port_route_add.rs:21`
- `lib/wasix/src/syscalls/wasix/port_route_add.rs:24`
- `lib/wasix/src/syscalls/wasix/port_gateway_set.rs:20`
- `lib/wasix/src/syscalls/wasix/sock_join_multicast_v6.rs:23`

There is also an internal correctness reference in `lib/wasix/src/net/mod.rs:176`, where `read_ip_port` already decodes IPv6 with `Ipv6Addr::from(octets)`, confirming the `transmute`-based readers were inconsistent and incorrect.

## Why This Is A Real Bug
The bug deterministically changes guest-provided IPv6 values during deserialization on common little-endian systems. That means route installation, gateway updates, interface address configuration, and multicast operations can target the wrong address even when the guest supplied valid network-order bytes. This is a concrete integrity failure in externally influenced networking state, not a theoretical portability concern.

## Fix Requirement
Replace host-endian reinterpretation of IPv6 octets with explicit big-endian decoding for each 16-bit segment before constructing `Ipv6Addr`.

## Patch Rationale
The patch removes `transmute`-style segment decoding and instead converts each two-byte chunk with `u16::from_be_bytes` before calling `Ipv6Addr::new`. This matches IPv6 network byte order, preserves behavior across host architectures, and aligns the affected readers with the already-correct `Ipv6Addr::from(octets)` logic used elsewhere in the same module.

## Residual Risk
None

## Patch
- Patch file: `030-ipv6-segments-decoded-using-host-endianness.patch`
- Updated `lib/wasix/src/net/mod.rs` to decode IPv6 segments in network byte order instead of host byte order.