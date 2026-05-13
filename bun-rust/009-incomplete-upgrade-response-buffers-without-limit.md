# Incomplete Upgrade Response Buffers Without Limit

## Classification

- Type: denial of service
- Severity: medium
- Confidence: certain

## Affected Locations

- `src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:891`
- `src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:915`
- (`:942`/`:969` proxy CONNECT response path has the same unbounded buffering but is left to a separate finding.)

## Summary

A malicious WebSocket server can send an incomplete HTTP 101 upgrade response indefinitely. The client accumulates partial response bytes in `me.body` and retries parsing on each read, but the vulnerable path does not enforce a maximum buffered header size before appending. This allows attacker-controlled pre-handshake memory growth until client process memory exhaustion.

## Provenance

- Verified by reproduced analysis.
- Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The victim opens a WebSocket connection to an attacker-controlled server.

## Proof

- `handle_data` parses the accumulated upgrade response buffer.
- If `picohttp::Response::parse` returns `ShortRead`, the function stores incomplete data in `me.body` and returns.
- On later reads, if `me.body` is nonempty, the function appends new bytes with `me.body.extend_from_slice(data)`.
- No maximum header or response size is checked before the patch.
- The early status check only rejects non-`HTTP/1.1 101 ` prefixes; an attacker can send that prefix and continue sending incomplete headers that never terminate.
- The 120-second socket timeout is not a byte cap and does not prevent memory exhaustion when data is sent continuously or fast enough.

## Why This Is A Real Bug

The WebSocket handshake is performed before the connection is handed to the normal WebSocket implementation, so all server response bytes in this phase are handled by the upgrade client. Incomplete HTTP responses are valid parser states represented by `ShortRead`, but retaining each incomplete fragment without a size limit lets a peer control the growth of `me.body`. Because this memory is allocated before handshake completion and before application-level acceptance, an attacker-controlled server can exhaust client memory with only a single outbound WebSocket connection from the victim.

## Fix Requirement

Enforce a maximum HTTP upgrade response header size before buffering incomplete response bytes, including both:

- the first incomplete chunk stored after `ShortRead`
- subsequent chunks appended to an existing buffered partial response

## Patch Rationale

The patch applies `bun_http::max_http_header_size()` as the cap for the pre-handshake HTTP upgrade response buffer. It checks the final buffered size before appending new data and rejects oversized incomplete responses with `ErrorCode::InvalidResponse`. `saturating_add` prevents integer overflow when calculating the prospective buffer length.

## Residual Risk

None

## Patch

```diff
diff --git a/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs b/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
index c3f48b94cd..c670c27a81 100644
--- a/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
+++ b/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
@@ -889,6 +889,11 @@ impl<const SSL: bool> HTTPClient<SSL> {
         let me = unsafe { &mut *this.as_ptr() };
         let mut body = data;
         if !me.body.is_empty() {
+            if me.body.len().saturating_add(data.len()) > bun_http::max_http_header_size() {
+                // SAFETY: `me`'s last use is above; no `&mut Self` spans this call.
+                unsafe { Self::terminate(this.as_ptr(), ErrorCode::InvalidResponse) };
+                return;
+            }
             me.body.extend_from_slice(data);
             body = &me.body;
         }
@@ -913,6 +918,11 @@ impl<const SSL: bool> HTTPClient<SSL> {
             }
             Err(picohttp::ParseResponseError::ShortRead) => {
                 if me.body.is_empty() {
+                    if data.len() > bun_http::max_http_header_size() {
+                        // SAFETY: `me`'s last use is above; no `&mut Self` spans this call.
+                        unsafe { Self::terminate(this.as_ptr(), ErrorCode::InvalidResponse) };
+                        return;
+                    }
                     me.body.extend_from_slice(data);
                 }
                 return;
```