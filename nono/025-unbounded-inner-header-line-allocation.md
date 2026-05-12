# Unbounded Inner Header Line Allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`crates/nono-proxy/src/tls_intercept/handle.rs:143`

## Summary

`forward_inner_request` parsed intercepted inner HTTP headers with `read_line(&mut line)` before enforcing `MAX_HEADER_SIZE`. An authenticated client controlling the inner HTTP stream could send a header line without `\n`, causing `read_line` to grow `line` without bound before the 64 KiB header cap was checked.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The attacker can authenticate to the proxy.
- The attacker can open an intercepted `CONNECT` tunnel.
- TLS interception succeeds.
- The attacker controls the inner HTTP request bytes sent through that tunnel.

## Proof

Reachability is confirmed through the authenticated intercepted `CONNECT` path:

- The outer `Proxy-Authorization` is validated before interception.
- `server.rs:746` calls `handle_intercept_connect`.
- `handle_intercept_connect` calls `forward_inner_request` at `crates/nono-proxy/src/tls_intercept/handle.rs:117`.
- `forward_inner_request` reads each inner header line with `buf_reader.read_line(&mut line).await?` at `crates/nono-proxy/src/tls_intercept/handle.rs:143`.
- The `MAX_HEADER_SIZE` check occurred only after `read_line` returned and after appending the full line to `header_bytes`.

Attack trigger:

```text
GET / HTTP/1.1\r\n
X-Fill: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

If the attacker withholds `\r\n` or `\n` after the oversized header value, `read_line` continues growing the fresh `String` until LF or EOF. The configured 64 KiB cap is not reached in program logic until after allocation has already occurred.

## Why This Is A Real Bug

`tokio::io::AsyncBufReadExt::read_line` appends to the provided `String` until it reads LF or reaches EOF. It does not enforce the caller's aggregate HTTP header limit.

The vulnerable code created a new `String` for each header line and called `read_line` without a bounded reader. Because the line-size and aggregate-size checks happened after `read_line` completed, a single unterminated inner header line could consume unbounded memory in the proxy task. Repeating or sustaining such connections can exhaust proxy memory and deny service.

## Fix Requirement

Header parsing must enforce a bound while reading, not only after a full line has been accumulated. The parser must reject once the next header line or total header block would exceed `MAX_HEADER_SIZE`.

## Patch Rationale

The patch wraps the `BufReader` in `take(MAX_HEADER_SIZE + 1)` for each header-line read:

```rust
let mut bounded_reader = (&mut buf_reader).take(limit as u64);
bounded_reader.read_line(&mut line).await?
```

This prevents `read_line` from growing `line` beyond the configured cap plus one sentinel byte. The patch then checks `header_bytes.len() + line.len() > MAX_HEADER_SIZE` before appending to `header_bytes` and returns `431 Request Header Fields Too Large` on violation.

Moving the empty-line check after the size check ensures that oversized input is rejected before being accepted as a terminator or appended.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-proxy/src/tls_intercept/handle.rs b/crates/nono-proxy/src/tls_intercept/handle.rs
index 59dbc34..79bff7f 100644
--- a/crates/nono-proxy/src/tls_intercept/handle.rs
+++ b/crates/nono-proxy/src/tls_intercept/handle.rs
@@ -22,7 +22,7 @@ use crate::route::RouteStore;
 use crate::tls_intercept::acceptor;
 use crate::tls_intercept::cert_cache::CertCache;
 use std::sync::Arc;
-use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
+use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
 use tokio::net::TcpStream;
 use tokio_rustls::TlsAcceptor;
 use tracing::{debug, warn};
@@ -140,12 +140,15 @@ where
     let mut header_bytes = Vec::new();
     loop {
         let mut line = String::new();
-        let n = buf_reader.read_line(&mut line).await?;
-        if n == 0 || line.trim().is_empty() {
+        let limit = MAX_HEADER_SIZE + 1;
+        let n = {
+            let mut bounded_reader = (&mut buf_reader).take(limit as u64);
+            bounded_reader.read_line(&mut line).await?
+        };
+        if n == 0 {
             break;
         }
-        header_bytes.extend_from_slice(line.as_bytes());
-        if header_bytes.len() > MAX_HEADER_SIZE {
+        if header_bytes.len() + line.len() > MAX_HEADER_SIZE {
             // Mirror the outer proxy's behaviour. We have to write into the
             // BufReader's inner stream — release it first.
             let buffered = buf_reader.buffer().to_vec();
@@ -156,6 +159,10 @@ where
             let _ = buffered;
             return Ok(());
         }
+        if line.trim().is_empty() {
+            break;
+        }
+        header_bytes.extend_from_slice(line.as_bytes());
     }
     let buffered = buf_reader.buffer().to_vec();
     drop(buf_reader);
```