# Unbounded RESP Aggregate Length Allocation

## Classification

denial of service, high severity, confidence certain

## Affected Locations

- `src/valkey/valkey_protocol.rs:380`
- `src/valkey/valkey_protocol.rs:429`
- `src/valkey/valkey_protocol.rs:451`
- `src/valkey/valkey_protocol.rs:470`
- `src/valkey/valkey_protocol.rs:519`
- `src/runtime/valkey_jsc/valkey.rs:849`
- `src/runtime/valkey_jsc/valkey.rs:852`

## Summary

`ValkeyReader` trusted RESP aggregate length headers before allocation. A malicious Redis-compatible server could send an aggregate header with an enormous element count, causing the client to call `Vec::with_capacity(len)` with attacker-controlled capacity before verifying that the response contains enough elements. This can trigger capacity-overflow panic, process abort, or memory exhaustion during response parsing.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The Valkey client parses responses from an attacker-controlled Redis-compatible server.
- The attacker can send malformed RESP aggregate responses with very large length headers.

## Proof

`ValkeyReader::read_value()` dispatches to `read_value_with_depth()` for server-controlled bytes.

For RESP arrays, the parser:

1. Reads the signed length.
2. Rejects only negative values.
3. Converts the value to `usize`.
4. Calls `Vec::with_capacity(len)` before validating that `len` elements are present.

The same unbounded preallocation pattern exists for RESP map, set, attribute, and push vectors.

A malicious server can send an aggregate header such as:

```text
*9223372036854775807\r\n
```

This reaches `Vec::with_capacity(i64::MAX as usize)`, which deterministically panics with capacity overflow. The project configures `panic = "abort"` for dev and release profiles in `Cargo.toml`, so this parser panic aborts the client process. Smaller but still huge counts can instead force attacker-sized allocation attempts and exhaust memory.

## Why This Is A Real Bug

The allocation occurs before the parser has proven that the input buffer can contain the declared number of RESP elements. Each RESP element requires at least one byte of input for its type marker, so an aggregate element count larger than the remaining unread buffer cannot be valid. Accepting such counts allows remote input to directly control vector capacity.

Because the parser is used on responses from a Redis-compatible server, a compromised, malicious, or attacker-controlled server can trigger this without client-side code execution. With `panic = "abort"`, a capacity-overflow panic is a process-level denial of service.

## Fix Requirement

Bound aggregate lengths before allocation and reject oversized counts. The parser must validate the declared aggregate count against a safe upper bound before calling `Vec::with_capacity`.

## Patch Rationale

The patch rejects aggregate counts larger than `self.buffer.len() - self.pos` before allocating. This is a sound per-buffer upper bound because every remaining RESP element must consume at least one byte. If the declared element count exceeds the remaining byte count, the response is necessarily malformed and must be rejected.

The fix is applied to:

- RESP Array: returns `RedisError::InvalidArray`
- RESP Map: returns `RedisError::InvalidMap`
- RESP Set: returns `RedisError::InvalidSet`
- RESP Attribute: returns `RedisError::InvalidAttribute`
- RESP Push: returns `RedisError::InvalidPush`

For Push, the patch converts `len` to `usize` once before validation and then computes `data_len` as `len - 1`, preserving the existing semantics that the first element is the push type.

## Residual Risk

None

## Patch

```diff
diff --git a/src/valkey/valkey_protocol.rs b/src/valkey/valkey_protocol.rs
index 4d98862b11..7ba37581fa 100644
--- a/src/valkey/valkey_protocol.rs
+++ b/src/valkey/valkey_protocol.rs
@@ -374,6 +374,9 @@ impl<'a> ValkeyReader<'a> {
                     return Ok(RESPValue::Array(Vec::new()));
                 }
                 let len = usize::try_from(len).expect("int cast");
+                if len > self.buffer.len() - self.pos {
+                    return Err(RedisError::InvalidArray);
+                }
                 let mut array = Vec::with_capacity(len);
                 // errdefer cleanup handled by Vec Drop on `?`
                 let mut i: usize = 0;
@@ -425,6 +428,9 @@ impl<'a> ValkeyReader<'a> {
                     return Err(RedisError::InvalidMap);
                 }
                 let len = usize::try_from(len).expect("int cast");
+                if len > self.buffer.len() - self.pos {
+                    return Err(RedisError::InvalidMap);
+                }
 
                 let mut entries = Vec::with_capacity(len);
                 // errdefer cleanup handled by Vec Drop on `?`
@@ -447,6 +453,9 @@ impl<'a> ValkeyReader<'a> {
                     return Err(RedisError::InvalidSet);
                 }
                 let len = usize::try_from(len).expect("int cast");
+                if len > self.buffer.len() - self.pos {
+                    return Err(RedisError::InvalidSet);
+                }
 
                 let mut set = Vec::with_capacity(len);
                 // errdefer cleanup handled by Vec Drop on `?`
@@ -466,6 +475,9 @@ impl<'a> ValkeyReader<'a> {
                     return Err(RedisError::InvalidAttribute);
                 }
                 let len = usize::try_from(len).expect("int cast");
+                if len > self.buffer.len() - self.pos {
+                    return Err(RedisError::InvalidAttribute);
+                }
 
                 let mut attrs = Vec::with_capacity(len);
                 // errdefer cleanup handled by Vec Drop on `?`
@@ -494,6 +506,10 @@ impl<'a> ValkeyReader<'a> {
                 if len < 0 || len == 0 {
                     return Err(RedisError::InvalidPush);
                 }
+                let len = usize::try_from(len).expect("int cast");
+                if len > self.buffer.len() - self.pos {
+                    return Err(RedisError::InvalidPush);
+                }
 
                 // First element is the push type
                 let push_type = self.read_value_with_depth(depth + 1)?;
@@ -515,7 +531,7 @@ impl<'a> ValkeyReader<'a> {
                 // errdefer free(push_type_dup) — drops automatically on `?`
 
                 // Read the rest of the data
-                let data_len = usize::try_from(len - 1).expect("int cast");
+                let data_len = len - 1;
                 let mut data = Vec::with_capacity(data_len);
                 // errdefer cleanup handled by Vec Drop on `?`
                 let mut i: usize = 0;
```