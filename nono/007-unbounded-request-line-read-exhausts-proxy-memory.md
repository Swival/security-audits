# Unbounded Request Line Read Exhausts Proxy Memory

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`crates/nono-proxy/src/server.rs:602`

## Summary

`handle_connection` read the HTTP request line with `read_line(&mut first_line)` before applying any size limit. A sandboxed child that can connect to the local proxy listener could send an oversized request line without a newline, causing unbounded growth of `first_line` and exhausting proxy memory before header-size enforcement ran.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

A sandboxed child process can open a TCP connection to the proxy listener.

## Proof

The proxy starts a local listener in `start()` and exposes the assigned port to the sandboxed child through proxy environment variables. For each accepted connection, `handle_connection` creates an empty `String` for the request line and calls `buf_reader.read_line(&mut first_line).await?`.

`read_line` appends bytes until newline, EOF, or error. In the vulnerable code path, `MAX_HEADER_SIZE` was only checked later while reading remaining headers into `header_bytes`. Therefore an attacker could connect to the proxy and send an arbitrarily large first line before the first newline, forcing unbounded allocation in `first_line`.

The reproduced trace confirmed the vulnerable operation at `crates/nono-proxy/src/server.rs:618`, with later header checks at `crates/nono-proxy/src/server.rs:625` and `crates/nono-proxy/src/server.rs:633`.

## Why This Is A Real Bug

The existing `MAX_HEADER_SIZE` guard did not cover the first request line. Because the first line is attacker-controlled and read before authentication, routing, or header rejection, a single reachable local client could cause unbounded proxy memory growth and deny service to the proxy process.

## Fix Requirement

Cap the first-line read before allocation can exceed the configured request/header size bound, and reject overlong first lines with an HTTP error.

## Patch Rationale

The patch reads the first line through `AsyncReadExt::take(MAX_HEADER_SIZE + 1)` and then rejects the request if more than `MAX_HEADER_SIZE` bytes were consumed. This preserves normal request parsing while ensuring the request line cannot grow without bound. Returning `431 Request Header Fields Too Large` is consistent with the existing response used when accumulated header bytes exceed `MAX_HEADER_SIZE`.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-proxy/src/server.rs b/crates/nono-proxy/src/server.rs
index 59da845..c507278 100644
--- a/crates/nono-proxy/src/server.rs
+++ b/crates/nono-proxy/src/server.rs
@@ -22,7 +22,7 @@ use std::net::SocketAddr;
 use std::path::PathBuf;
 use std::sync::atomic::{AtomicUsize, Ordering};
 use std::sync::Arc;
-use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
+use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
 use tokio::net::TcpListener;
 use tokio::sync::watch;
 use tracing::{debug, info, warn};
@@ -615,7 +615,16 @@ async fn handle_connection(mut stream: tokio::net::TcpStream, state: &ProxyState
     // to prevent data loss (BufReader may read ahead into the body).
     let mut buf_reader = BufReader::new(&mut stream);
     let mut first_line = String::new();
-    buf_reader.read_line(&mut first_line).await?;
+    let n = (&mut buf_reader)
+        .take((MAX_HEADER_SIZE + 1) as u64)
+        .read_line(&mut first_line)
+        .await?;
+    if n > MAX_HEADER_SIZE {
+        drop(buf_reader);
+        let response = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
+        stream.write_all(response.as_bytes()).await?;
+        return Ok(());
+    }
 
     if first_line.is_empty() {
         return Ok(()); // Client disconnected
```