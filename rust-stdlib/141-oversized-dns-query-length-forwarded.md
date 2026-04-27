# Oversized DNS Query Length Forwarded

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/dns.rs:69`

## Summary

`lookup_host` copied at most 4096 bytes into a fixed 4096-byte DNS query buffer, but forwarded `query.as_bytes().len()` to `lend_mut`. For queries longer than 4096 bytes, the Xous DNS resolver received a mutable lend whose actual buffer length was 4096 bytes while the advertised query length was larger.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`lookup_host` is called with a query string longer than 4096 bytes.

## Proof

The DNS query buffer is `LookupHostQuery([u8; 4096])`.

Before the patch, `lookup_host` populated the buffer with:

```rust
for (query_byte, result_byte) in query.as_bytes().iter().zip(result.data.0.iter_mut()) {
    *result_byte = *query_byte;
}
```

The `zip` truncates the copy to `result.data.0.len()`, so only the first 4096 bytes are written.

The function then called:

```rust
lend_mut(
    dns_server(),
    DnsLendMut::RawLookup.into(),
    &mut result.data.0,
    0,
    query.as_bytes().len(),
)
```

For a 4097-byte query, the lent buffer remains 4096 bytes, but the final length argument is 4097. The Xous `lend_mut_impl` path sends the actual buffer pointer and length separately from the caller-provided final argument, so the DNS resolver receives inconsistent bounds.

## Why This Is A Real Bug

The lent-buffer contract requires the valid byte count to fit within the lent memory. This code violated that invariant for oversized hostnames by advertising more valid query bytes than the mutable lend contains.

That can cause the DNS resolver to read past the lent query buffer, reject the message unexpectedly, or otherwise mishandle oversized input. The path is reachable from every Xous DNS lookup using `lookup_host`.

## Fix Requirement

Reject DNS queries whose byte length exceeds `result.data.0.len()` before copying the query and before calling `lend_mut`.

## Patch Rationale

The patch adds an explicit length check immediately after constructing the 4096-byte result buffer:

```rust
if query.as_bytes().len() > result.data.0.len() {
    return Err(io::const_error!(io::ErrorKind::InvalidInput, "DNS query too long"));
}
```

This preserves valid 4096-byte boundary behavior and prevents any oversized query from reaching `lend_mut` with an advertised length larger than the lent buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/dns.rs b/library/std/src/sys/net/connection/xous/dns.rs
index b139376f597..0583c0ceac2 100644
--- a/library/std/src/sys/net/connection/xous/dns.rs
+++ b/library/std/src/sys/net/connection/xous/dns.rs
@@ -61,6 +61,9 @@ fn next(&mut self) -> Option<SocketAddr> {
 
 pub fn lookup_host(query: &str, port: u16) -> io::Result<LookupHost> {
     let mut result = LookupHost { data: LookupHostQuery([0u8; 4096]), offset: 0, count: 0, port };
+    if query.as_bytes().len() > result.data.0.len() {
+        return Err(io::const_error!(io::ErrorKind::InvalidInput, "DNS query too long"));
+    }
 
     // Copy the query into the message that gets sent to the DNS server
     for (query_byte, result_byte) in query.as_bytes().iter().zip(result.data.0.iter_mut()) {
```