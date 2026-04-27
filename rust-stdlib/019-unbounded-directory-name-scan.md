# Unbounded Directory Name Scan

## Classification

High-severity vulnerability: out-of-bounds read / undefined behavior in Hermit `std::fs::read_dir` directory entry parsing.

## Affected Locations

- `library/std/src/sys/fs/hermit.rs:211`

## Summary

Hermit directory iteration parsed `dirent64.d_name` with `CStr::from_ptr`, which scans memory until the first NUL byte. The scan was not bounded by `d_reclen` or by the backing directory buffer length. If `getdents64` returns a `dirent64` record whose `d_name` is not NUL-terminated inside the record buffer, iterating `std::fs::read_dir` can read past the allocated directory buffer.

## Provenance

- Verified by source review and reproduced from the provided data-flow evidence.
- Scanner provenance: Swival Security Scanner, https://swival.dev
- Confidence: certain.

## Preconditions

- `hermit_abi::getdents64` returns a `dirent64` record whose `d_name` lacks a NUL byte within the returned record buffer.

## Proof

- `readdir` fills a `Vec<u8>` with bytes returned by `hermit_abi::getdents64`.
- `ReadDir::next` casts bytes from that vector to `dirent64`.
- For the selected entry, the original code called:
  ```rust
  CStr::from_ptr(&dir.d_name as *const _ as *const c_char).to_bytes()
  ```
- `CStr::from_ptr` computes the string length by searching for a NUL terminator and requires the pointer to be valid through that terminator.
- The original parsing did not constrain the search to `dir.d_reclen` or `self.inner.dir.len()`.
- Therefore, an unterminated `d_name` causes the NUL search to continue past the directory record and potentially past the vector allocation, producing an out-of-bounds read / UB.

## Why This Is A Real Bug

The unsafe `CStr::from_ptr` contract is violated under the stated syscall-output precondition. The caller provides only a pointer to `d_name`, not a bounded slice, so the length computation can inspect memory beyond the valid directory buffer. This is reachable from safe Rust through Hermit `std::fs::read_dir` iteration once the malformed `getdents64` buffer is present.

## Fix Requirement

Directory entry name parsing must be bounded to the current record and must reject malformed records:

- Validate `d_reclen` before using it.
- Ensure the computed record end does not exceed `self.inner.dir.len()`.
- Search for the NUL terminator only within `offset + d_name_offset..record_end`.
- Return an error if the record is invalid or the name is not NUL-terminated within bounds.

## Patch Rationale

The patch replaces unbounded pointer-based parsing with bounded slice parsing:

- Removes the unnecessary `c_char` import.
- Computes the `d_name` offset with `mem::offset_of!(dirent64, d_name)`.
- Converts `dir.d_reclen` to `usize` and checks `offset.checked_add(reclen)` for overflow.
- Rejects records where `reclen < name_offset` or `record_end > self.inner.dir.len()`.
- Calls `CStr::from_bytes_until_nul` on the bounded record-name slice.
- Returns `InvalidData` instead of invoking UB when the record or name is malformed.

This preserves valid directory entry behavior while preventing scans outside the returned directory buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/hermit.rs b/library/std/src/sys/fs/hermit.rs
index 5992766b5a4..29a2a66ef87 100644
--- a/library/std/src/sys/fs/hermit.rs
+++ b/library/std/src/sys/fs/hermit.rs
@@ -1,4 +1,4 @@
-use crate::ffi::{CStr, OsStr, OsString, c_char};
+use crate::ffi::{CStr, OsStr, OsString};
 use crate::fs::TryLockError;
 use crate::io::{self, BorrowedCursor, Error, ErrorKind, IoSlice, IoSliceMut, SeekFrom};
 use crate::os::hermit::ffi::OsStringExt;
@@ -200,12 +200,33 @@ fn next(&mut self) -> Option<io::Result<DirEntry>> {
             if counter == self.pos {
                 self.pos += 1;
 
-                // After dirent64, the file name is stored. d_reclen represents the length of the dirent64
-                // plus the length of the file name. Consequently, file name has a size of d_reclen minus
-                // the size of dirent64. The file name is always a C string and terminated by `\0`.
-                // Consequently, we are able to ignore the last byte.
-                let name_bytes =
-                    unsafe { CStr::from_ptr(&dir.d_name as *const _ as *const c_char).to_bytes() };
+                let name_offset = mem::offset_of!(dirent64, d_name);
+                let reclen = usize::from(dir.d_reclen);
+                let Some(record_end) = offset.checked_add(reclen) else {
+                    return Some(Err(io::const_error!(
+                        ErrorKind::InvalidData,
+                        "directory entry record is invalid",
+                    )));
+                };
+                if reclen < name_offset || record_end > self.inner.dir.len() {
+                    return Some(Err(io::const_error!(
+                        ErrorKind::InvalidData,
+                        "directory entry record is invalid",
+                    )));
+                }
+
+                let name = match CStr::from_bytes_until_nul(
+                    &self.inner.dir[offset + name_offset..record_end],
+                ) {
+                    Ok(name) => name,
+                    Err(_) => {
+                        return Some(Err(io::const_error!(
+                            ErrorKind::InvalidData,
+                            "directory entry name is not NUL-terminated",
+                        )));
+                    }
+                };
+                let name_bytes = name.to_bytes();
                 let entry = DirEntry {
                     root: self.inner.root.clone(),
                     ino: dir.d_ino,
```