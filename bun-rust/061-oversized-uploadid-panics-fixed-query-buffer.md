# oversized UploadId panics fixed query buffer

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/runtime/webcore/s3/multipart.rs:244`

`src/runtime/webcore/s3/multipart.rs:342`

`src/runtime/webcore/s3/multipart.rs:351`

`src/runtime/webcore/s3/multipart.rs:687`

`src/runtime/webcore/s3/multipart.rs:712`

`src/runtime/webcore/s3/multipart.rs:800`

`src/runtime/webcore/s3/multipart.rs:831`

## Summary

A malicious S3-compatible backend could return an oversized `<UploadId>` in the multipart initiation response. The code stored that value without a length bound, then later formatted it into fixed 2048-byte query buffers using `write!(...).expect("unreachable")`. If the `UploadId` exceeded the remaining buffer space, formatting failed and `expect` panicked, denying service during active multipart upload handling.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Client performs multipart upload through an attacker-controlled S3-compatible endpoint.
- The endpoint returns a multipart initiation response containing an overlong `<UploadId>`.
- Upload flow proceeds to upload, commit, or rollback requests that include the attacker-supplied `UploadId` in query parameters.

## Proof

- `start_multi_part_request_result` parses `response.body` between `<UploadId>` and `</UploadId>` and assigns it to `this.upload_id` without a length limit.
- After initiation succeeds, state becomes `MultipartCompleted` and `drain_enqueued_parts(0)` starts queued parts.
- `UploadPart::perform` formats `?partNumber=...&uploadId=...&x-id=UploadPart` into `[u8; 2048]`.
- The formatter writes through `&mut [u8]`; when the fixed slice is exhausted, `write!` returns an error.
- The error is passed to `.expect("unreachable")`, causing a process panic.
- An ASCII `UploadId` of roughly more than 2009 bytes overflows the part request query buffer.
- The same fixed-buffer and `expect("unreachable")` pattern is present in commit and rollback request construction.

## Why This Is A Real Bug

The `UploadId` is remote-controlled by the S3-compatible backend and is trusted after only checking that it is non-empty. The later query construction assumes the value fits inside a fixed-size 2048-byte stack buffer, but that assumption is false for oversized backend responses. Rust’s slice-backed `write!` reports failure when capacity is exhausted, and the subsequent `expect("unreachable")` converts that recoverable error into a panic. This makes denial of service reachable from a malicious endpoint during normal multipart upload flow.

## Fix Requirement

Reject or safely encode and length-bound the `UploadId` before any fixed-buffer formatting path can use it.

## Patch Rationale

The patch adds `MAX_UPLOAD_ID_LEN` and rejects multipart initiation responses where `upload_id.len() > Self::MAX_UPLOAD_ID_LEN`. The chosen 2000-byte cap leaves room inside the 2048-byte query buffers for the fixed query parameter text and part number used by `UploadPart::perform`, while also protecting commit and rollback paths that format `?uploadId=...`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/webcore/s3/multipart.rs b/src/runtime/webcore/s3/multipart.rs
index 14fe8d607f..28c58e0a9f 100644
--- a/src/runtime/webcore/s3/multipart.rs
+++ b/src/runtime/webcore/s3/multipart.rs
@@ -182,6 +182,7 @@ impl MultiPartUpload {
     const MIN_SINGLE_UPLOAD_SIZE: usize = MultiPartUploadOptions::MIN_SINGLE_UPLOAD_SIZE;
     const DEFAULT_PART_SIZE: usize = MultiPartUploadOptions::DEFAULT_PART_SIZE;
     const MAX_QUEUE_SIZE: usize = MultiPartUploadOptions::MAX_QUEUE_SIZE as usize;
+    const MAX_UPLOAD_ID_LEN: usize = 2000;
     // `const AWS = S3Credentials;` — type alias unused in this file; dropped.
 
     // bun.ptr.RefCount(Self, "ref_count", deinit, .{}) — intrusive refcount.
@@ -690,7 +691,7 @@ impl MultiPartUpload {
                     }
                 }
                 this.uploadid_buffer = response.body;
-                if this.upload_id.is_empty() {
+                if this.upload_id.is_empty() || this.upload_id.len() > Self::MAX_UPLOAD_ID_LEN {
                     // Unknown type of response error from AWS
                     scoped_log!(
                         S3MultiPartUpload,
```