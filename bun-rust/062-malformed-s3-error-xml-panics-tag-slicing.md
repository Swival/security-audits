# Malformed S3 Error XML Panics Tag Slicing

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/webcore/s3/simple_request.rs:239`

## Summary

`S3HttpSimpleTask::error_with_body` parsed S3 error XML by independently locating `<Code>` and `</Code>`, then slicing between them without verifying that the closing tag occurs after the opening tag value. A malicious S3-compatible endpoint could return malformed XML with `</Code>` before `<Code>`, causing a Rust slice bounds panic in the response callback.

## Provenance

Verified from supplied source, reproducer, and patch. Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Caller sends an S3 request to an attacker-controlled S3-compatible endpoint.
- The endpoint returns a non-success S3 response that reaches `S3HttpSimpleTask::error_with_body`.
- The response body contains `</Code>` before `<Code>`, for example `</Code><Code>x`.

## Proof

`S3HttpSimpleTask::on_response` calls `error_with_body` for non-success result handling and non-200/404 status handling, including paths at `src/runtime/webcore/s3/simple_request.rs:349` and `src/runtime/webcore/s3/simple_request.rs:350`.

`error_with_body` reads attacker-controlled response bytes from `self.result.body` at `src/runtime/webcore/s3/simple_request.rs:250`.

Before the patch, it performed:

```rust
if let Some(start) = strings::index_of(bytes, b"<Code>") {
    if let Some(end) = strings::index_of(bytes, b"</Code>") {
        code = &bytes[start + b"<Code>".len()..end];
        has_error_code = true;
    }
}
```

For body `</Code><Code>x`:

- `start = 7`
- `end = 0`
- `start + b"<Code>".len() = 13`
- slice range is `13..0`

That invalid range panics during Rust slice indexing.

## Why This Is A Real Bug

The response body is controlled by the S3-compatible server. The vulnerable code executes during normal S3 error handling for attacker-controlled non-success responses. The panic occurs in the response callback, and the repository configures `panic = "abort"` for release and dev profiles in `Cargo.toml:151` and `Cargo.toml:154`, so exploitation can abort the process and deny service.

## Fix Requirement

Only slice the `<Code>` value when the located `</Code>` offset is greater than or equal to the start of the value after `<Code>`.

## Patch Rationale

The patch computes `value_start` once and checks `end >= value_start` before slicing for both the `<Code>` and `<Message>` tag pairs (the `<Message>` block has the identical flaw — `</Message>` before `<Message>` would also panic). Malformed bodies with an earlier closing tag are ignored for code/message extraction, preserving the default error code path and avoiding panic. Well-formed bodies continue to parse exactly as before.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/webcore/s3/simple_request.rs b/src/runtime/webcore/s3/simple_request.rs
index 3420c6d789..1ee81a0981 100644
--- a/src/runtime/webcore/s3/simple_request.rs
+++ b/src/runtime/webcore/s3/simple_request.rs
@@ -252,14 +252,20 @@ impl S3HttpSimpleTask {
             if !bytes.is_empty() {
                 message = bytes;
                 if let Some(start) = strings::index_of(bytes, b"<Code>") {
+                    let value_start = start + b"<Code>".len();
                     if let Some(end) = strings::index_of(bytes, b"</Code>") {
-                        code = &bytes[start + b"<Code>".len()..end];
-                        has_error_code = true;
+                        if end >= value_start {
+                            code = &bytes[value_start..end];
+                            has_error_code = true;
+                        }
                     }
                 }
                 if let Some(start) = strings::index_of(bytes, b"<Message>") {
+                    let value_start = start + b"<Message>".len();
                     if let Some(end) = strings::index_of(bytes, b"</Message>") {
-                        message = &bytes[start + b"<Message>".len()..end];
+                        if end >= value_start {
+                            message = &bytes[value_start..end];
+                        }
                     }
                 }
             }
```