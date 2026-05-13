# S3 Blob Reads Leak Downloaded Bodies

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/runtime/webcore/Blob.rs:2520`

## Summary

S3-backed `Blob` read methods leaked every successfully downloaded response body. `S3BlobDownloadTask::on_s3_download_resolved` wrapped the S3 response in `ManuallyDrop`, borrowed `response.body.list` as bytes, and resolved the read without transferring ownership to any finalizer-backed owner. A malicious S3-compatible backend could return large successful bodies and cause repeated reads to exhaust process memory.

## Provenance

Reported and verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

An application reads attacker-controlled S3 blobs through Blob methods such as `.text()`, `.json()`, `.arrayBuffer()`, `.bytes()`, or `.formData()`.

## Proof

The reproduced path is:

`do_read_from_s3` -> `S3BlobDownloadTask::init` -> S3 download callback -> `S3BlobDownloadTask::on_s3_download_resolved`.

On success, the vulnerable code did:

```rust
let mut response = core::mem::ManuallyDrop::new(response);
let bytes = &mut response.body.list[..];
let value = JSPromise::wrap(global, |_g| Ok(this.call_handler(bytes)))?;
```

Because `response` was `ManuallyDrop`, `response.body.list` was never dropped. The inline comment explicitly stated that the body buffer was intentionally leaked into JSC's external view. Each successful attacker-sized S3 response therefore leaked one `Vec<u8>` allocation.

## Why This Is A Real Bug

The S3 backend controls the successful response body size. Blob read methods are expected to release native download buffers after the resulting JS value no longer needs them. Instead, the success path permanently leaked the buffer. Repeated reads grow process memory monotonically, producing an attacker-triggered memory exhaustion denial of service.

## Fix Requirement

The downloaded body must be transferred into an owner whose lifetime is tied to the JS view or Blob storage and whose finalizer/drop path frees the allocation. The success path must not use `ManuallyDrop` to suppress destruction without replacing it with finalizer-backed ownership.

## Patch Rationale

The patch moves `response.body.list` into a `Store` via `Store::init(response.body.list)`, then points the task Blob at that store before invoking the existing read handler. This gives the downloaded bytes a normal Blob store owner and lets existing store-backed JS external buffer/string lifetime handling retain and free the allocation correctly.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/webcore/Blob.rs b/src/runtime/webcore/Blob.rs
index c29a4e08d8..378d34cf1d 100644
--- a/src/runtime/webcore/Blob.rs
+++ b/src/runtime/webcore/Blob.rs
@@ -5657,22 +5657,18 @@ impl S3BlobDownloadTask {
         let global = global_ref.get();
         match result {
             crate::webcore::__s3_client::S3DownloadResult::Success(response) => {
-                // PORT NOTE: Zig leaks `response.body` here (no Drop on
-                // MutableString). The handler runs `to*WithBytes` with
-                // `Lifetime::Clone`, which builds an external JS
-                // string/ArrayBuffer that *aliases* `body.list` (no copy) and
-                // anchors its lifetime to the S3 store ref — the body buffer
-                // itself is intentionally leaked into JSC's external view.
-                // Dropping `response` would free the Vec while JSC still
-                // points at it (mimalloc reuses the first 8 bytes for its
-                // free-list link → "\0…\0n!" for a 10-byte body). Match Zig:
-                // leak the body.
-                let mut response = core::mem::ManuallyDrop::new(response);
-                let bytes = &mut response.body.list[..];
+                let store = Store::init(response.body.list);
+                let bytes = match store.data_mut() {
+                    store::Data::Bytes(bytes) => std::ptr::from_mut(bytes.as_array_list()),
+                    _ => unreachable!(),
+                };
+                this.blob.store.set(Some(store));
                 if this.blob.size.get() == MAX_SIZE {
                     this.blob.size.set(bytes.len() as SizeType);
                 }
-                let value = JSPromise::wrap(global, |_g| Ok(this.call_handler(bytes)))?;
+                let value = JSPromise::wrap(global, |_g| {
+                    Ok(this.call_handler(unsafe { &mut *bytes }))
+                })?;
                 this.promise.resolve(global, value)?;
             }
             crate::webcore::__s3_client::S3DownloadResult::NotFound(err)
```