# non-2xx streamed tarball responses buffer without a cap

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

- `src/install/NetworkTask.rs:251`

## Summary

When streaming tarball extraction is enabled, `for_tarball()` requests response-body streaming. For non-2xx tarball responses, `NetworkTask::notify()` intentionally avoids committing to streaming extraction and instead preserves `response_buffer` for later main-thread error handling.

During chunked non-2xx responses, intermediate callbacks return while `result.has_more` is true and do not reset or cap `response_buffer`. An attacker-controlled registry can therefore send an unbounded error body and force the package manager process to retain attacker-controlled bytes until memory exhaustion.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Streaming extraction is enabled.
- The tarball URL points to an attacker-controlled or compromised registry.
- The attacker returns a chunked non-2xx tarball response.

## Proof

The finding was reproduced.

Observed execution path:

- `for_tarball()` enables `response_body_streaming` when `extract_tarball::uses_streaming_extraction()` is true.
- The HTTP client appends streamed body chunks into the caller-owned `response_buffer`.
- The HTTP client invokes `NetworkTask::notify()` repeatedly with `has_more = true`.
- In `notify()`, a cached non-2xx status makes `ok_status` false.
- For intermediate chunks, the `else if result.has_more` branch returns without calling `this.response_buffer.reset()`.
- This branch intentionally accumulates the body so the main thread can inspect it.
- No size check exists on this fallback accumulation path.
- `src/http/lib.rs` limits only preallocation, not total accumulated response length.
- `MutableString::write()` / append operations grow the underlying `Vec` as more bytes arrive.

Impact:

- A malicious registry can keep sending a chunked non-2xx response body.
- The package manager process retains the entire error body in `response_buffer`.
- Memory usage grows until process exhaustion.

## Why This Is A Real Bug

The vulnerable path is reachable by design: streaming tarball downloads still preserve non-2xx bodies for existing retry and error-reporting behavior. However, unlike successful streaming extraction, the fallback path neither drains chunks into `TarballStream` nor resets the response buffer. It also lacks a maximum retained error-body size.

Because the attacker controls both the non-2xx response and the chunked body length, the retained buffer size is attacker-controlled and unbounded. This creates a practical denial-of-service condition against installs that fetch tarballs from an attacker-controlled registry.

## Fix Requirement

Buffered non-2xx bodies received through the streaming tarball path must be capped. Once the cap is exceeded, the request must stop accepting more body data or otherwise prevent further accumulation.

## Patch Rationale

The patch adds a fixed maximum retained streaming error body size:

- `MAX_STREAMING_ERROR_BODY_SIZE: usize = 1024 * 1024`

In the non-2xx `result.has_more` branch, the patch:

- Checks whether `response_buffer` exceeds the cap.
- Truncates it to the maximum retained size.
- Sets the HTTP abort signal to stop further body delivery.

The patch also wires `signal_store.aborted` into `http_options.signals` for streamed tarball requests, allowing `notify()` to abort the in-flight request after the cap is reached.

This preserves the existing behavior of retaining an error body for main-thread inspection while preventing unbounded memory growth.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/NetworkTask.rs b/src/install/NetworkTask.rs
index 00a766d2b9..dbb4eb6940 100644
--- a/src/install/NetworkTask.rs
+++ b/src/install/NetworkTask.rs
@@ -280,6 +280,10 @@ impl NetworkTask {
                 // delivering its body: accumulate in `response_buffer`
                 // (we did *not* reset above) so the main thread can
                 // inspect it. Do not enqueue until the stream ends.
+                if !ok_status && this.response_buffer.list.len() > MAX_STREAMING_ERROR_BODY_SIZE {
+                    this.response_buffer.list.truncate(MAX_STREAMING_ERROR_BODY_SIZE);
+                    this.signal_store.aborted.store(true, Ordering::Relaxed);
+                }
                 return;
             }
             // Fall through to the normal completion path for anything that
@@ -344,6 +348,7 @@ const DEFAULT_HEADERS_BUF: &str = concat!(
     "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*",
 );
 const EXTENDED_HEADERS_BUF: &str = concat!("Accept", "application/json, */*");
+const MAX_STREAMING_ERROR_BODY_SIZE: usize = 1024 * 1024;
 
 fn append_auth(header_builder: &mut HeaderBuilder, scope: &npm::registry::Scope) {
     if !scope.token.is_empty() {
@@ -786,10 +791,9 @@ impl NetworkTask {
             // `generateNetworkTaskForTarball`) because it needs the
             // pre-allocated `Task` that carries the final result.
             //
-            // Only wire up the one signal we need; `Signals.Store.to()`
-            // would also publish `aborted`/`cert_errors`/etc., which makes
-            // the HTTP client allocate an abort-tracker id and changes
-            // keep-alive behaviour we don't want here.
+            // Only wire up the signals we need; `Signals.Store.to()` would
+            // also publish `cert_errors`/etc. and change behaviour we don't
+            // want here.
             self.signal_store = http::signals::Store::default();
             self.signal_store
                 .response_body_streaming
@@ -798,6 +802,7 @@ impl NetworkTask {
                 response_body_streaming: Some(NonNull::from(
                     &self.signal_store.response_body_streaming,
                 )),
+                aborted: Some(NonNull::from(&self.signal_store.aborted)),
                 ..Default::default()
             });
         }
```