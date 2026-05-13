# Malformed S3 Error Message Panics

## Classification

Denial of service, medium severity, confidence: certain.

## Affected Locations

`src/runtime/webcore/s3/download_stream.rs:132`

## Summary

A malformed S3 error XML body can cause a Rust slice-bounds panic during S3 download error parsing. If an attacker-controlled S3-compatible endpoint returns `</Message>` before `<Message>`, the parser computes a slice whose start is greater than its end. Because the workspace uses `panic = "abort"`, this panic terminates the process.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client downloads from an attacker-controlled S3-compatible endpoint.
- The endpoint returns a non-success final response status.
- The final response body contains `</Message>` before `<Message>`.

## Proof

`process_http_callback` appends response body bytes into `reported_response_buffer`.

On the final callback, `on_response` calls `report_progress` with `has_more == false`. For non-`200`/`204`/`206` status codes, `report_progress` parses the buffered error body.

Before the patch, parsing did this:

```rust
if let Some(start) = strings::index_of(bytes, b"<Message>") {
    if let Some(end) = strings::index_of(bytes, b"</Message>") {
        message = &bytes[start + b"<Message>".len()..end];
    }
}
```

The opening and closing tags were searched independently from the start of `bytes`. With a body containing `</Message>` before `<Message>`, `end < start + b"<Message>".len()`, so the slice panics.

The same pattern existed for `<Code>` / `</Code>`.

## Why This Is A Real Bug

The panic is reachable from attacker-controlled response bytes when using an attacker-controlled S3-compatible endpoint. The malformed body does not need to be valid XML; it only needs to place the closing tag before the opening tag.

The impact is process termination because `Cargo.toml` configures `panic = "abort"` for dev and release profiles. This turns a parsing bug into a practical denial of service.

## Fix Requirement

Search for each closing tag only after the end of its corresponding opening tag, then slice using bounds derived from that suffix search.

## Patch Rationale

The patch computes `value_start` immediately after the opening tag and searches for the closing tag in `&bytes[value_start..]`. The returned `end` is relative to that suffix, so the final slice is:

```rust
&bytes[value_start..value_start + end]
```

This guarantees the slice end is never before the slice start for matched tags. It also applies the same correction to `<Code>` parsing, which had the same independent-open/close search pattern.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/webcore/s3/download_stream.rs b/src/runtime/webcore/s3/download_stream.rs
index 4ffb81e7cc..49a7d50fd3 100644
--- a/src/runtime/webcore/s3/download_stream.rs
+++ b/src/runtime/webcore/s3/download_stream.rs
@@ -126,14 +126,16 @@ impl S3HttpDownloadStreamingTask {
                             message = bytes;
 
                             if let Some(start) = strings::index_of(bytes, b"<Code>") {
-                                if let Some(end) = strings::index_of(bytes, b"</Code>") {
-                                    code = &bytes[start + b"<Code>".len()..end];
+                                let value_start = start + b"<Code>".len();
+                                if let Some(end) = strings::index_of(&bytes[value_start..], b"</Code>") {
+                                    code = &bytes[value_start..value_start + end];
                                     _has_body_code = true;
                                 }
                             }
                             if let Some(start) = strings::index_of(bytes, b"<Message>") {
-                                if let Some(end) = strings::index_of(bytes, b"</Message>") {
-                                    message = &bytes[start + b"<Message>".len()..end];
+                                let value_start = start + b"<Message>".len();
+                                if let Some(end) = strings::index_of(&bytes[value_start..], b"</Message>") {
+                                    message = &bytes[value_start..value_start + end];
                                     _has_body_message = true;
                                 }
                             }
```