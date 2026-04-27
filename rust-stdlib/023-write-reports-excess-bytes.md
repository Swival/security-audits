# write reports excess bytes

## Classification

Data integrity bug, medium severity, certain confidence.

## Affected Locations

`library/std/src/sys/net/connection/xous/tcpstream.rs:280`

## Summary

`TcpStream::write` on Xous trusts the byte count returned in `send_request.raw[4..8]` after a successful `net_server` send. The actual request length is capped to `buf_len = min(4096, buf.len())`, but the returned count is not bounded before being reported to callers. If `net_server` returns a success count larger than `buf_len`, `write` reports bytes that were never supplied to the server.

## Provenance

Finding verified from source review and reproduced reasoning.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `net_server` returns success.
- The success byte count encoded in `send_request.raw[4..8]` is greater than the requested `buf_len`.

## Proof

Caller data enters `TcpStream::write` as `buf`.

`library/std/src/sys/net/connection/xous/tcpstream.rs:253` copies caller bytes into `send_request.raw`.

`library/std/src/sys/net/connection/xous/tcpstream.rs:254` caps the send size:

```rust
let buf_len = send_request.raw.len().min(buf.len());
```

`library/std/src/sys/net/connection/xous/tcpstream.rs:256` passes only `buf_len` bytes to `net_server` through `lend_mut`.

On success, `library/std/src/sys/net/connection/xous/tcpstream.rs:280` returns the raw server-provided count:

```rust
Ok(u32::from_le_bytes([
    send_request.raw[4],
    send_request.raw[5],
    send_request.raw[6],
    send_request.raw[7],
]) as usize)
```

There is no check that this count is `<= buf_len` or `<= buf.len()`.

The reproduced impact is that a successful response with an excessive count causes `TcpStream::write` to report bytes not supplied to `net_server`. For buffers larger than 4096, `write_all` can skip unsent bytes. For counts larger than the caller buffer, `write_all` can panic when slicing at `buf[n..]`.

## Why This Is A Real Bug

The `Write::write` contract requires `Ok(n)` to satisfy `n <= buf.len()`. This implementation can return `Ok(n)` where `n > buf.len()` and also where `n > buf_len`, the actual number of bytes made available to `net_server`.

Because higher-level write helpers rely on the returned count to advance through the caller buffer, over-reporting corrupts stream write semantics and can cause skipped data or panic.

## Fix Requirement

Clamp or reject any successful returned byte count greater than `buf_len`.

## Patch Rationale

The patch clamps the decoded success count to `buf_len` before returning it:

```rust
Ok((u32::from_le_bytes([
    send_request.raw[4],
    send_request.raw[5],
    send_request.raw[6],
    send_request.raw[7],
]) as usize)
    .min(buf_len))
```

This guarantees `TcpStream::write` never reports more bytes than were actually requested from `net_server`. Since `buf_len <= buf.len()`, the `Write::write` contract is also preserved.

## Residual Risk

None

## Patch

`023-write-reports-excess-bytes.patch`

```diff
diff --git a/library/std/src/sys/net/connection/xous/tcpstream.rs b/library/std/src/sys/net/connection/xous/tcpstream.rs
index 4df75453d1f..3f574807236 100644
--- a/library/std/src/sys/net/connection/xous/tcpstream.rs
+++ b/library/std/src/sys/net/connection/xous/tcpstream.rs
@@ -277,12 +277,13 @@ pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
                 return Err(io::const_error!(io::ErrorKind::InvalidInput, "error when sending"));
             }
         }
-        Ok(u32::from_le_bytes([
+        Ok((u32::from_le_bytes([
             send_request.raw[4],
             send_request.raw[5],
             send_request.raw[6],
             send_request.raw[7],
         ]) as usize)
+            .min(buf_len))
     }
 
     pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
```