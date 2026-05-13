# Streaming decompression has no output limit

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`src/zstd/lib.rs:278`

## Summary

`decompress_alloc` routed unknown-size or over-16MiB zstd frames into streaming decompression, but the streaming path had no decompressed-output cap. An attacker-supplied zstd payload could force unbounded `Vec` growth until process memory exhaustion.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

The victim calls `decompress_alloc` on attacker-supplied zstd data.

## Proof

`decompress_alloc` used `ZSTD_findDecompressedSize` and selected streaming decompression when the reported size was `ZSTD_CONTENTSIZE_UNKNOWN` or greater than `MAX_PREALLOCATE_SIZE` (`16 * 1024 * 1024`).

That path initialized an empty `Vec`, constructed `ZstdReaderArrayList`, and called `read_all(true)`. Inside `read_all`, each `ZSTD_decompressStream` iteration reserved spare capacity, committed `out_buf.pos` bytes into the vector, and incremented `total_out`. No code compared `total_out`, the vector length, or the next write size against a maximum.

The reproducer validated equivalent zstd behavior: a 2.03KiB zstd frame with unknown content size made `ZSTD_findDecompressedSize` return `ZSTD_CONTENTSIZE_UNKNOWN`, then `ZSTD_decompressStream` produced 64MiB. Scaling the payload drives unbounded allocation. The 16MiB constant only avoided preallocation; it did not bound streaming output.

## Why This Is A Real Bug

This is externally reachable through public APIs that pass caller-controlled buffers into `decompress_alloc`, including `Bun.zstdDecompressSync` and async `Bun.zstdDecompress`.

The allocation failure is process-impacting because `Vec::reserve` is infallible in the relevant helper path; allocation failure becomes a process-level failure rather than a handled decompression error. Therefore attacker-controlled compressed bytes can cause memory exhaustion and terminate the process.

## Fix Requirement

Enforce a maximum decompressed output size in the streaming decompression path before reserving capacity and before committing produced bytes.

## Patch Rationale

The patch adds `max_output_size` to `ZstdReaderArrayList`, defaulting to `usize::MAX` to preserve existing behavior for other users of the reader.

`decompress_alloc` sets `reader.max_output_size = MAX_PREALLOCATE_SIZE`, so the fallback streaming path is bounded by the same 16MiB safety limit used for the known-size fast path.

`read_all` now:

- Computes remaining allowed output with `checked_sub`.
- Fails with `ZstdDecompressionError` if the limit is already reached.
- Reserves at most `remaining.min(4096)` bytes.
- Caps `ZSTD_outBuffer.size` to the remaining allowance.
- Checks `total_out + bytes_written` with `checked_add` before committing output.

This converts oversized decompression into a handled error instead of unbounded allocation.

## Residual Risk

None

## Patch

```diff
diff --git a/src/zstd/lib.rs b/src/zstd/lib.rs
index a4d91eebae..677af864d9 100644
--- a/src/zstd/lib.rs
+++ b/src/zstd/lib.rs
@@ -279,6 +279,7 @@ pub fn decompress_alloc(src: &[u8]) -> core::result::Result<Vec<u8>, ZstdError>
         let mut list: Vec<u8> = Vec::new();
         // PORT NOTE: Zig's `errdefer list.deinit(allocator)` is implicit — `list` drops on `?`.
         let mut reader = ZstdReaderArrayList::init(src, &mut list)?;
+        reader.max_output_size = MAX_PREALLOCATE_SIZE;
 
         reader.read_all(true)?;
         drop(reader);
@@ -319,6 +320,7 @@ pub struct ZstdReaderArrayList<'a> {
     pub state: State,
     pub total_out: usize,
     pub total_in: usize,
+    pub max_output_size: usize,
 }
 
 impl<'a> ZstdReaderArrayList<'a> {
@@ -350,6 +352,7 @@ impl<'a> ZstdReaderArrayList<'a> {
             state: State::Uninitialized,
             total_out: 0,
             total_in: 0,
+            max_output_size: usize::MAX,
         }))
     }
 
@@ -387,9 +390,19 @@ impl<'a> ZstdReaderArrayList<'a> {
                 return Ok(());
             }
 
+            let remaining = match self.max_output_size.checked_sub(self.total_out) {
+                Some(remaining) if remaining > 0 => remaining,
+                _ => {
+                    self.state = State::Error;
+                    return Err(ZstdError::ZstdDecompressionError);
+                }
+            };
+
             // SAFETY: write-only spare; ZSTD_decompressStream initializes the
             // first `out_buf.pos` bytes.
-            let spare = unsafe { bun_core::vec::reserve_spare_bytes(self.list_ptr, 4096) };
+            let spare = unsafe {
+                bun_core::vec::reserve_spare_bytes(self.list_ptr, remaining.min(4096))
+            };
             let mut in_buf = c::ZSTD_inBuffer {
                 src: next_in.as_ptr().cast::<c_void>(),
                 size: next_in.len(),
@@ -397,7 +410,7 @@ impl<'a> ZstdReaderArrayList<'a> {
             };
             let mut out_buf = c::ZSTD_outBuffer {
                 dst: spare.as_mut_ptr().cast::<c_void>(),
-                size: spare.len(),
+                size: spare.len().min(remaining),
                 pos: 0,
             };
 
@@ -412,6 +425,14 @@ impl<'a> ZstdReaderArrayList<'a> {
 
             let bytes_written = out_buf.pos;
             let bytes_read = in_buf.pos;
+            if self
+                .total_out
+                .checked_add(bytes_written)
+                .map_or(true, |total| total > self.max_output_size)
+            {
+                self.state = State::Error;
+                return Err(ZstdError::ZstdDecompressionError);
+            }
             // SAFETY: ZSTD_decompressStream wrote exactly `bytes_written` initialized bytes
             // into the spare capacity starting at the previous len.
             unsafe { bun_core::vec::commit_spare(self.list_ptr, bytes_written) };
```