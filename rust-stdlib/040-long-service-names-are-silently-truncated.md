# Long Service Names Are Silently Truncated

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/os/xous/services.rs:38`

## Summary

Xous service-name connection helpers accepted names longer than the documented 64-byte maximum and silently truncated them to the first 64 bytes before querying the name server.

This could cause a caller requesting an overlong name to connect to, or block waiting for, a different service identified by the 64-byte prefix.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller passes a service name whose byte length is greater than `NAME_MAX_LENGTH`.
- The call reaches public `connect` or `try_connect`, which delegate into `ns::connect_with_name_impl`.

## Proof

The public wrappers are reachable:

- `connect` calls `ns::connect_with_name`.
- `try_connect` calls `ns::try_connect_with_name`.
- Both reach `connect_with_name_impl`.

Before the patch, `ConnectRequest::new` copied only bytes paired with the fixed 64-byte destination:

```rust
for (&src_byte, dest_byte) in name_bytes.iter().zip(&mut cr.data[0..NAME_MAX_LENGTH]) {
    *dest_byte = src_byte;
}
```

Bytes after offset 63 were discarded.

The encoded name length was also clamped:

```rust
name.len().min(NAME_MAX_LENGTH)
```

The same clamped length was passed to `lend_mut`:

```rust
lend_mut(cid, opcode, &mut request.data, 0, name.len().min(NAME_MAX_LENGTH))
```

Therefore an input longer than 64 bytes was sent to the name server as its 64-byte prefix, not rejected.

## Why This Is A Real Bug

The public documentation for `connect` states that server names are arbitrary-length strings “up to 64 bytes in length”.

The implementation did not enforce that contract. It coerced invalid input into a different valid lookup key. For an input like `PREFIX + suffix`, where `PREFIX` is exactly 64 bytes, the caller could unintentionally operate on `PREFIX` instead of the requested overlong name.

This is behaviorally significant because:

- `connect` may block waiting for the truncated prefix.
- `try_connect` may return a connection for the truncated prefix.
- The caller receives no indication that the supplied name was invalid.

## Fix Requirement

Reject service names whose byte length exceeds `NAME_MAX_LENGTH` before constructing or sending the `ConnectRequest`.

## Patch Rationale

The patch adds an explicit length check at the start of `connect_with_name_impl`:

```rust
if name.len() > NAME_MAX_LENGTH {
    return None;
}
```

This is the correct enforcement point because both blocking and non-blocking public paths pass through `connect_with_name_impl`.

Returning `None` matches the existing function contract for failed lookups and prevents:

- Truncated request construction.
- Clamped length encoding.
- Name-server lookup using an unintended prefix.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/xous/services.rs b/library/std/src/os/xous/services.rs
index 0681485ea06..d01c65181fd 100644
--- a/library/std/src/os/xous/services.rs
+++ b/library/std/src/os/xous/services.rs
@@ -54,6 +54,10 @@ pub fn new(name: &str) -> Self {
     }
 
     pub fn connect_with_name_impl(name: &str, blocking: bool) -> Option<Connection> {
+        if name.len() > NAME_MAX_LENGTH {
+            return None;
+        }
+
         let mut request = ConnectRequest::new(name);
         let opcode = if blocking {
             6 /* BlockingConnect */
```