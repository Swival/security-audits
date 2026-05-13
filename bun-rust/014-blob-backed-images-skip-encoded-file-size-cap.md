# Blob-Backed Images Skip Encoded File Size Cap

## Classification

Denial of service, medium severity.

## Affected Locations

`src/runtime/image/Image.rs:1300`

## Summary

`Bun.Image` enforces `MAX_INPUT_FILE_BYTES` for path-backed image inputs before reading file contents, but Blob-backed inputs from `Bun.file()` bypass that guard. A file-backed Blob larger than the 256 MiB encoded input cap can be fully read into memory before image validation runs, allowing attacker-influenced image paths to trigger process memory exhaustion.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The application constructs `Bun.Image` from an attacker-influenced `Bun.file()` Blob.
- A terminal image operation is invoked, such as `.bytes()`, `.buffer()`, `.blob()`, `.metadata()`, `.toBase64()`, `.dataURL()`, `.placeholder()`, or `.write()`.

## Proof

Reachable path:

- `source_from_js` stores non-memory Blob inputs as `Source::Blob` when `blob.store` exists.
- `schedule` diverts `Source::Blob` into `BlobReadChain::start`.
- `BlobReadChain::start` calls `blob.read_bytes_to_handler`.
- `BlobReadChain::on_read_bytes_impl` accepted `ReadBytesResult::Ok(bytes)` and swapped it into `Source::Owned(bytes)` without checking `MAX_INPUT_FILE_BYTES`.
- The existing 256 MiB encoded input cap only ran for `Source::Path` in `PipelineTask::run` before `file.read_to_end`.
- File-backed Blob reads use `ReadFile` and can preallocate/read the whole file from `st_size`, so oversized files can be materialized before image guards run.

Representative trigger:

```js
await new Bun.Image(Bun.file(attackerControlledPath)).bytes();
```

The same bypass applies to `.metadata()` and other terminal operations because all `Source::Blob` terminals pass through `BlobReadChain`.

## Why This Is A Real Bug

The code has an explicit encoded-file-size guard, `MAX_INPUT_FILE_BYTES`, intended to prevent large encoded inputs from being materialized before header or pixel guards run. That guard is enforced for path sources but not for file-backed Blob sources representing the same underlying file class. Since Blob reading completes before the image pipeline sees the bytes, an oversized file-backed Blob can consume large process memory before `maxPixels`, decode checks, or the path-specific size cap can reject it.

## Fix Requirement

Enforce `MAX_INPUT_FILE_BYTES` on Blob read completion before storing Blob bytes in `Source::Owned` or scheduling the image pipeline.

## Patch Rationale

The patch adds a size check immediately after `ReadBytesResult::Ok(bytes)` is received in `BlobReadChain::on_read_bytes_impl`:

```rust
if bytes.len() as u64 > MAX_INPUT_FILE_BYTES {
    drop(deliver);
    let _ = outer.reject(
        global,
        Ok(reject_error(global, codecs::Error::TooManyPixels)),
    );
    return;
}
```

This is the earliest point in the Blob read chain where the completed byte vector size is available. Rejecting there prevents the oversized buffer from being cached as `Source::Owned` and prevents re-entry into the image pipeline. The rejection reuses the same `TooManyPixels` error path used by the existing encoded-file cap for path-backed inputs.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/image/Image.rs b/src/runtime/image/Image.rs
index 7d129f0ebc..2e778170af 100644
--- a/src/runtime/image/Image.rs
+++ b/src/runtime/image/Image.rs
@@ -1316,6 +1316,14 @@ impl<'a> BlobReadChain<'a> {
 
         match r {
             ReadBytesResult::Ok(bytes) => {
+                if bytes.len() as u64 > MAX_INPUT_FILE_BYTES {
+                    drop(deliver);
+                    let _ = outer.reject(
+                        global,
+                        Ok(reject_error(global, codecs::Error::TooManyPixels)),
+                    );
+                    return;
+                }
                 // Concurrent terminals can have started multiple BlobReadChains
                 // (no in-flight serialisation — `start()` re-enters every time
                 // it sees `.blob`). The FIRST resolver wins and swaps to
```