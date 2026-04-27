# IPv6 DNS record parsing skips first byte

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/net/connection/xous/dns.rs:38`

## Summary

The Xous DNS `LookupHost` iterator corrupts IPv6 DNS results. After reading an IPv6 record tag, `next` advances `self.offset` to the first IPv6 address byte, but then copies from `self.offset + 1`. This drops the first address byte and includes one byte after the 16-byte IPv6 payload.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- DNS server returns at least one IPv6 record.
- Caller consumes the result through `LookupHost::next`.

## Proof

`lookup_host` stores the DNS server response in `result.data.0`, sets `result.offset = 2`, and returns `LookupHost`.

In the IPv6 branch of `LookupHost::next`, the record tag `6` is consumed first:

```rust
self.offset += 1;
```

At that point, `self.offset` points at the first byte of the 16-byte IPv6 address. The affected code then copies from the wrong range:

```rust
self.data.0[(self.offset + 1)..(self.offset + 16 + 1)]
```

That range contains bytes `addr[1..16]` plus the following buffer byte, not `addr[0..16]`.

The reproduced example encoded `2001:db8::1` followed by byte `0xaa`. The existing logic parsed it as:

```text
expected 2001:db8::1
parsed   10d:b800::1aa
```

## Why This Is A Real Bug

The IPv4 branch starts copying immediately after the tag, but the IPv6 branch incorrectly skips one more byte. The bounds check validates `self.offset + 16`, confirming the intended 16-byte payload begins at `self.offset`. The later copy contradicts that invariant by reading `self.offset + 1` through `self.offset + 16`.

As a result, all IPv6 addresses returned by this iterator are malformed whenever IPv6 DNS records are present.

## Fix Requirement

Copy exactly 16 bytes starting at `self.offset`:

```rust
self.data.0[self.offset..(self.offset + 16)]
```

Do not add one to the start or end of the IPv6 payload range.

## Patch Rationale

The patch changes only the IPv6 copy range:

```diff
- self.data.0[(self.offset + 1)..(self.offset + 16 + 1)]
+ self.data.0[self.offset..(self.offset + 16)]
```

This aligns the copy with the existing control flow:

- `self.offset += 1` consumes the record tag.
- The bounds check ensures 16 bytes are available from `self.offset`.
- The copy now reads those exact 16 IPv6 address bytes.
- `self.offset += 16` then advances past the record payload.

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