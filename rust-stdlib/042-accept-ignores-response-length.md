# accept ignores response length

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/tcplistener.rs:124`

## Summary

`TcpListener::accept` accepted a successful `net_server` response without checking the returned valid byte count. The code then parsed fixed response offsets through byte 21, allowing truncated successful responses to be interpreted using stale zero-initialized buffer bytes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`net_server` returns success from `lend_mut` with a valid length shorter than the fields parsed by `TcpListener::accept`.

## Proof

`accept` receives response bytes from `net_server` via `lend_mut`. The original code bound the returned length as `_valid`, intentionally ignored it, then accepted success when `receive_request.raw[0] == 0`.

After that, it parsed:

- stream fd from `raw[1..3]`
- address family from `raw[3]`
- IP bytes from `raw[4..20]`
- port from `raw[20..22]`

A concrete malformed response is `Ok((_, 4))` with bytes `[0, fd_lo, fd_hi, 4]`. The original code treats this as a successful IPv4 accept and constructs peer metadata from zero-initialized trailing bytes, yielding `0.0.0.0:0` instead of rejecting the truncated response.

## Why This Is A Real Bug

The response-length value returned by `lend_mut` defines how many bytes are valid. Parsing beyond that length accepts data that was not supplied by `net_server`.

This is reachable on every successful `TcpListener::accept` path. It is not memory-unsafe because the receive buffer is initialized to zero, but it can return a `TcpStream` with corrupted peer metadata and potentially corrupted stream fd or port fields.

## Fix Requirement

Require the valid response length to cover all parsed accept fields before parsing them. If fewer than 22 bytes are valid for a successful accept response, return `io::ErrorKind::InvalidData`.

## Patch Rationale

The patch changes `_valid` to `valid` and adds a success-path length check before any fixed-offset parsing. The minimum valid length is 22 bytes because the code reads through `raw[20..22]` for the peer port and may read up to `raw[18..20]` for IPv6 address segments.

This preserves existing error handling while rejecting malformed successful responses before stale buffer contents can influence returned socket metadata.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/tcplistener.rs b/library/std/src/sys/net/connection/xous/tcplistener.rs
index 8818ef2ca9a..7e88c91a761 100644
--- a/library/std/src/sys/net/connection/xous/tcplistener.rs
+++ b/library/std/src/sys/net/connection/xous/tcplistener.rs
@@ -121,7 +121,7 @@ pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
             receive_request.raw[0] = 1;
         }
 
-        if let Ok((_offset, _valid)) = crate::os::xous::ffi::lend_mut(
+        if let Ok((_offset, valid)) = crate::os::xous::ffi::lend_mut(
             services::net_server(),
             services::NetLendMut::StdTcpAccept(self.fd.load(Ordering::Relaxed)).into(),
             &mut receive_request.raw,
@@ -141,6 +141,9 @@ pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
                 }
             } else {
                 // accept successful
+                if valid < 22 {
+                    return Err(io::const_error!(io::ErrorKind::InvalidData, "invalid response"));
+                }
                 let rr = &receive_request.raw;
                 let stream_fd = u16::from_le_bytes(rr[1..3].try_into().unwrap());
                 let port = u16::from_le_bytes(rr[20..22].try_into().unwrap());
```