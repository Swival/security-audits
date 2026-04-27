# IPv6 DNS Record Boundary Check Permits Panic

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/dns.rs:38`

## Summary

The Xous DNS `LookupHost` iterator validates that 16 IPv6 address bytes remain, but then slices one byte past the validated range. A DNS response that places an IPv6 record tag at the end of the 4096-byte buffer can make iteration panic with an out-of-bounds slice.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- DNS server returns byte `6` at offset `4079` or equivalent boundary position in the lookup response.
- Caller invokes `lookup_host` and iterates the returned `LookupHost`.

## Proof

`lookup_host` gives the DNS service mutable access to the full 4096-byte response buffer through `lend_mut` at `library/std/src/sys/net/connection/xous/dns.rs:70`.

After the response, `lookup_host` only checks `result.data.0[0] == 0` before returning success at `library/std/src/sys/net/connection/xous/dns.rs:78`. Iteration starts at offset `2` at `library/std/src/sys/net/connection/xous/dns.rs:85`.

In `LookupHost::next`, the IPv6 branch increments `self.offset` past the record type byte, checks:

```rust
if self.offset + 16 > self.data.0.len() {
    return None;
}
```

For a crafted response where the IPv6 tag is at offset `4079`, `self.offset` becomes `4080`. The check passes because `4080 + 16 == 4096`.

The code then slices:

```rust
self.data.0[(self.offset + 1)..(self.offset + 16 + 1)]
```

This evaluates to `4081..4097`, which exceeds the 4096-byte buffer and panics with:

```text
range end index 4097 out of range for slice of length 4096
```

Reachability is source-supported because `count` is loaded from byte `1` but `Iterator::next` never consults it, so it does not bound iteration.

## Why This Is A Real Bug

The bounds check and the slice use different start positions. The check validates bytes `self.offset..self.offset + 16`, but the slice reads `self.offset + 1..self.offset + 17`.

The DNS response buffer is externally populated by the DNS service through `lend_mut`, and `lookup_host` accepts the response as long as byte `0` indicates success. Therefore, malformed or hostile DNS response data can reach the iterator and trigger a panic during normal iteration.

## Fix Requirement

The IPv6 address copy must read exactly the 16 bytes validated by the existing bounds check, or the bounds check must be widened to cover the actual slice. The preferred fix is to slice from `self.offset..self.offset + 16`, matching the existing validation and preserving IPv6 record parsing semantics.

## Patch Rationale

The patch changes the IPv6 copy range from:

```rust
(self.offset + 1)..(self.offset + 16 + 1)
```

to:

```rust
self.offset..(self.offset + 16)
```

This makes the slice exactly match the previously validated 16-byte range after `self.offset` has already been advanced past the IPv6 type byte. At the boundary case, the slice becomes `4080..4096`, which is valid and copies the final 16 bytes of the buffer without panicking.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/dns.rs b/library/std/src/sys/net/connection/xous/dns.rs
index b139376f597..3163bc57aae 100644
--- a/library/std/src/sys/net/connection/xous/dns.rs
+++ b/library/std/src/sys/net/connection/xous/dns.rs
@@ -43,7 +43,7 @@ fn next(&mut self) -> Option<SocketAddr> {
                     return None;
                 }
                 let mut new_addr = [0u8; 16];
-                for (src, octet) in self.data.0[(self.offset + 1)..(self.offset + 16 + 1)]
+                for (src, octet) in self.data.0[self.offset..(self.offset + 16)]
                     .iter()
                     .zip(new_addr.iter_mut())
                 {
```