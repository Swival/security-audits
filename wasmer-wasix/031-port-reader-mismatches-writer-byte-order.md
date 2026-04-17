# Port reader mismatches writer byte order

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/net/mod.rs:146`

## Summary
- `write_ip_port` serializes `__wasi_addr_port_t.port` in big-endian order, but `read_ip_port` decodes the same two bytes with native-endian order.
- On little-endian hosts, any address round-tripped through these helpers changes port value, causing socket operations to target the wrong port.

## Provenance
- Verified from the provided reproducer summary and source inspection in `lib/wasix/src/net/mod.rs:146`
- Reference: https://swival.dev

## Preconditions
- A little-endian host reads a `__wasi_addr_port_t` value previously written by this module.

## Proof
- `write_ip_port` stores `port.to_be_bytes()` into `u.octs[0..2]`.
- `read_ip_port` reconstructs the port with `u16::from_ne_bytes([o[0], o[1]])`.
- For bytes `[0x12, 0x34]`, the writer encodes port `0x1234` (`4660`), while a little-endian reader decodes `0x3412` (`13330`).
- The mismatch is reachable through the shared address helpers used by bind/connect/send paths for both IPv4 and IPv6 addresses.

## Why This Is A Real Bug
- The module’s own writer defines the on-wire/in-memory byte order for this field as big-endian.
- Reading the same field with native-endian order is inconsistent and host-dependent.
- This produces silent corruption of destination or bound ports, which can misroute traffic and break reuse of returned socket addresses.

## Fix Requirement
- Decode the port in `read_ip_port` with `u16::from_be_bytes` so the reader matches the existing writer.

## Patch Rationale
- The patch changes only the port decode path in `read_ip_port` to use big-endian decoding.
- This aligns read behavior with `write_ip_port`, preserves network byte order semantics, and removes host-endianness dependence.

## Residual Risk
- None

## Patch
```diff
diff --git a/lib/wasix/src/net/mod.rs b/lib/wasix/src/net/mod.rs
index 0000000..0000000 100644
--- a/lib/wasix/src/net/mod.rs
+++ b/lib/wasix/src/net/mod.rs
@@ -146,7 +146,7 @@ pub fn read_ip_port(addr: &__wasi_addr_port_t) -> std::io::Result<SocketAddr> {
     let o = addr.u.octs;
-    let port = u16::from_ne_bytes([o[0], o[1]]);
+    let port = u16::from_be_bytes([o[0], o[1]]);
     match addr.tag {
         __WASI_ADDRESS_FAMILY_INET4 => {
             let ip = Ipv4Addr::new(o[2], o[3], o[4], o[5]);
```