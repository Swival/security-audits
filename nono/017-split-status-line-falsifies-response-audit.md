# Split Status Line Falsifies Response Audit

## Classification

Repudiation, medium severity. Confidence: certain.

## Affected Locations

`crates/nono-proxy/src/forward.rs:256`

## Summary

An attacker-controlled upstream can split the HTTP response status line across multiple TCP reads so the proxy audits `502` while forwarding the real successful response to the client.

The proxy previously parsed the status code only from the first upstream read. If that read contained an incomplete status line such as `HTTP/1.1 20`, parsing failed and defaulted to `502`. The same bytes were still written to the client, and later reads completed the valid response, so the audit trail diverged from the response actually delivered.

## Provenance

Verified by reproduction from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The proxy forwards a request to an upstream controlled by the attacker.
- The attacker can control how the upstream response bytes are split across reads.
- The first upstream read does not contain a complete valid HTTP status line.

## Proof

The vulnerable flow is:

- `forward_request` calls `stream_response` and stores its returned status.
- `stream_response` reads from the upstream and, before the patch, calls `parse_response_status(&buf[..n])` only for the first read.
- `parse_response_status` returns `502` when the provided bytes do not contain a complete valid `HTTP/... <3-digit-code>` status line.
- `stream_response` still writes that first partial chunk to `inbound`, then writes all later chunks unchanged.
- `forward_request` logs the status returned by `stream_response`.

A malicious upstream can split:

```text
HTTP/1.1 200 OK\r\n
```

so the first read contains only an incomplete prefix. The parser records `502`, but the client receives the concatenated valid `HTTP/1.1 200 OK` response.

Reproduction confirmed that the client/audit divergence occurs: the L7 audit event records `502` while the client receives the real upstream response.

## Why This Is A Real Bug

The audit status is intended to represent the response delivered to the client. In this case, the proxy forwards the exact bytes that form a valid successful HTTP response, but logs a synthetic failure status caused only by read-boundary timing.

TCP read boundaries are not HTTP message boundaries. Treating the first read as the complete status line lets an upstream falsify audit evidence without changing the response seen by the client.

## Fix Requirement

Buffer upstream response bytes until the full HTTP status line is available before parsing and auditing the status code.

The fix must preserve streaming behavior by continuing to forward every upstream chunk to the inbound client as it is read.

## Patch Rationale

The patch replaces the `first_chunk` parse with bounded status-line accumulation:

- Adds a `status_line` buffer capped at 512 bytes, well above the 64-byte window already used by `parse_response_status`.
- Tracks whether the status has been parsed with `status_parsed`.
- Extends the buffer with upstream bytes until `\r`, `\n`, or the cap is reached.
- Parses the status only after a line terminator or the cap is observed, so an upstream that never sends CR/LF cannot grow the buffer unbounded.
- Continues writing every upstream read to the client immediately.

This makes the audited status independent of arbitrary upstream read splitting while preserving transparent streaming for response bodies.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-proxy/src/forward.rs b/crates/nono-proxy/src/forward.rs
index 704d256..2a133df 100644
--- a/crates/nono-proxy/src/forward.rs
+++ b/crates/nono-proxy/src/forward.rs
@@ -231,9 +231,9 @@ where
 
 /// Stream the upstream response back to the inbound sink.
 ///
-/// Returns the HTTP status code parsed from the first chunk. Streams
-/// chunked / SSE / HTTP-streaming bodies transparently because we never
-/// buffer the body — each upstream read is mirrored to the inbound write.
+/// Returns the HTTP status code parsed from the status line. Streams
+/// chunked / SSE / HTTP-streaming bodies transparently because we only
+/// buffer the status line — each upstream read is mirrored to the inbound write.
 async fn stream_response<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
 where
     U: AsyncRead + AsyncWrite + Unpin,
@@ -241,7 +241,9 @@ where
 {
     let mut buf = [0u8; 8192];
     let mut status_code: u16 = 502;
-    let mut first_chunk = true;
+    const STATUS_LINE_MAX: usize = 512;
+    let mut status_line: Vec<u8> = Vec::new();
+    let mut status_parsed = false;
 
     loop {
         let n = match upstream.read(&mut buf).await {
@@ -253,9 +255,15 @@ where
             }
         };
 
-        if first_chunk {
-            status_code = parse_response_status(&buf[..n]);
-            first_chunk = false;
+        if !status_parsed {
+            let take = (STATUS_LINE_MAX - status_line.len()).min(n);
+            status_line.extend_from_slice(&buf[..take]);
+            if status_line.iter().any(|&b| b == b'\r' || b == b'\n')
+                || status_line.len() >= STATUS_LINE_MAX
+            {
+                status_code = parse_response_status(&status_line);
+                status_parsed = true;
+            }
         }
 
         inbound.write_all(&buf[..n]).await?;
```