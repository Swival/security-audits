# archive files trusts declared entry size

## Classification

Denial of service, medium severity.

## Affected Locations

`src/runtime/api/Archive.rs:1095`

## Summary

`Archive.files()` parsed attacker-supplied archive bytes and trusted each regular entry's declared size before validating that the archive actually contained that data. For a regular file entry, `FilesContext::do_run` converted `entry_ref.size()` to `usize` and immediately allocated `vec![0u8; size]`. A small tar or tar.gz could declare a very large file size and force a large zero-filled allocation on the worker thread, causing process memory exhaustion, panic, or abort.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The application calls `Archive.files()` on attacker-supplied archive bytes.
- The attacker controls an archive entry header for a regular file.
- The entry can declare a large size without providing that many bytes.

## Proof

`Archive.files()` starts `start_files_task`, whose `FilesContext::do_run` opens the archive from `self.store.shared_view()` and iterates libarchive headers.

For each regular entry:

- `entry_ref.filetype()` is checked against `FILETYPE_REGULAR`.
- Optional glob filtering may skip unmatched paths.
- `entry_ref.size().max(0)` is converted to `usize`.
- Before any successful `archive.read_data` proves the declared bytes exist, the old code executed `data = vec![0u8; size]`.

That made allocation size attacker-controlled archive metadata. A crafted archive with a huge regular-file size field could trigger memory exhaustion even when the actual archive body was small or truncated.

## Why This Is A Real Bug

The vulnerable operation occurred before data validation. `vec![0u8; size]` is an eager, infallible allocation sized entirely from an untrusted tar header. Existing controls did not bound this path:

- Non-regular entries were skipped, but regular entries remained vulnerable.
- Glob filtering only helped when the attacker-controlled path did not match.
- No per-entry or total output size cap existed before allocation.
- `archive.read_data` was called only after the large allocation had already occurred.

This is a reachable attacker-triggered denial of service for applications that process untrusted archives with `Archive.files()`.

## Fix Requirement

Do not allocate a buffer based solely on the archive entry's declared size. Read entry data incrementally using a bounded temporary buffer, and grow the output only by bytes actually returned from `archive.read_data`, with allocation failure converted into a normal `OutOfMemory` error.

## Patch Rationale

The patch replaces the eager `vec![0u8; size]` allocation with a fixed 64 KiB stack buffer. Each loop iteration reads at most the smaller of the remaining declared size and the fixed buffer length. The result vector grows only after libarchive returns actual bytes.

The patch also uses `data.try_reserve(bytes_read)` before appending. Allocation failure is mapped to `bun_alloc::AllocError`, preserving the existing `FilesContext::run` behavior that converts allocation errors into `FilesError::OutOfMemory`.

This removes the direct attacker-controlled allocation while preserving the API behavior of returning file contents in memory for successfully read entries.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/api/Archive.rs b/src/runtime/api/Archive.rs
index abff1907d2..4fdf4be14f 100644
--- a/src/runtime/api/Archive.rs
+++ b/src/runtime/api/Archive.rs
@@ -1184,13 +1184,14 @@ impl FilesContext {
             let size: usize = usize::try_from(entry_ref.size().max(0)).expect("int cast");
             let mtime: i64 = entry_ref.mtime();
 
-            // Read data first before allocating path
+            // Read data incrementally so untrusted entry sizes don't drive allocation.
             let mut data: Vec<u8> = Vec::new();
             if size > 0 {
-                data = vec![0u8; size];
                 let mut total_read: usize = 0;
+                let mut buf = [0u8; 64 * 1024];
                 while total_read < size {
-                    let read = archive.read_data(&mut data[total_read..]);
+                    let to_read = (size - total_read).min(buf.len());
+                    let read = archive.read_data(&mut buf[..to_read]);
                     if read < 0 {
                         // Read error - returned as a normal Result (not a Zig error), so the
                         // errdefer above won't fire. Free the current buffer and all previously
@@ -1207,7 +1208,11 @@ impl FilesContext {
                     if read == 0 {
                         break;
                     }
-                    total_read += usize::try_from(read).expect("int cast");
+                    let bytes_read = usize::try_from(read).expect("int cast");
+                    data.try_reserve(bytes_read)
+                        .map_err(|_| bun_alloc::AllocError)?;
+                    data.extend_from_slice(&buf[..bytes_read]);
+                    total_read += bytes_read;
                 }
             }
             // errdefer free(data) — handled by Drop
```