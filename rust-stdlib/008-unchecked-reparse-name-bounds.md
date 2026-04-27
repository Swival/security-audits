# Unchecked Reparse Name Bounds

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/fs/windows.rs:773`

## Summary

`readlink` trusted reparse-point `SubstituteNameOffset` and `SubstituteNameLength` values returned by `DeviceIoControl(FSCTL_GET_REPARSE_POINT)` before constructing a UTF-16 slice. Malformed reparse data could make safe public `readlink(path)` perform out-of-bounds pointer arithmetic and slice creation inside unsafe code.

## Provenance

Verified from the supplied source, reproduced finding, and patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

A caller reads a symlink or mount point whose reparse buffer contains malformed name offsets or lengths.

## Proof

`File::reparse_point` fills a fixed 16 KiB `space` buffer through `DeviceIoControl(FSCTL_GET_REPARSE_POINT)` and returns the raw `REPARSE_DATA_BUFFER` pointer plus byte count.

Before the patch, `File::readlink` discarded the returned byte count and directly read:

- `SubstituteNameOffset`
- `SubstituteNameLength`
- `PathBuffer`

It then computed:

```rust
let subst_ptr = path_buffer.add(subst_off.into());
let subst = slice::from_raw_parts_mut(subst_ptr, subst_len as usize);
```

No check proved that `subst_off + subst_len` stayed within the returned reparse data or within the `PathBuffer`.

A concrete malformed symlink reparse buffer with `ReparseTag = IO_REPARSE_TAG_SYMLINK`, `SubstituteNameOffset = 0xfffe`, and `SubstituteNameLength = 2` causes the offset to become 32767 UTF-16 elements. This advances far beyond `MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16384` bytes and violates the safety requirements of `ptr.add` and `slice::from_raw_parts_mut`.

## Why This Is A Real Bug

The vulnerable operation is reachable through the public Windows `readlink(path)` path. The unsafe block constructs a mutable slice from untrusted filesystem metadata without validating the OS-returned byte count, reparse data length, offset alignment, or offset-plus-length bounds.

Once the invalid slice exists, later operations such as `starts_with`, `subst[1] = ...`, and `OsString::from_wide(subst)` may read or write outside the initialized buffer.

## Fix Requirement

Validate the returned byte count and all name offset/length fields before pointer arithmetic or slice construction. Reject malformed reparse data if:

- the returned byte count is smaller than the reparse buffer header
- the returned byte count exceeds the local buffer
- `ReparseDataLength` exceeds the returned payload
- the tag-specific `PathBuffer` is not present
- substitute name offset or length is not UTF-16 aligned
- `SubstituteNameOffset + SubstituteNameLength` overflows or exceeds `PathBuffer`

## Patch Rationale

The patch keeps `bytes` from `reparse_point` and validates it against the local buffer and `ReparseDataLength`. It computes the tag-specific `PathBuffer` offset with `offset_of!`, derives the actual available `PathBuffer` byte length, and rejects malformed buffers with `ERROR_INVALID_REPARSE_DATA`.

The patch also keeps substitute name offset and length in bytes until after validation. Only after confirming even alignment and in-bounds `offset + length` does it divide by two and construct the UTF-16 slice.

This directly prevents out-of-bounds pointer arithmetic and slice creation for malformed reparse buffers.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/windows.rs b/library/std/src/sys/fs/windows.rs
index 74854cdeb49..356bd285d4b 100644
--- a/library/std/src/sys/fs/windows.rs
+++ b/library/std/src/sys/fs/windows.rs
@@ -723,26 +723,49 @@ fn reparse_point(
     fn readlink(&self) -> io::Result<PathBuf> {
         let mut space =
             Align8([MaybeUninit::<u8>::uninit(); c::MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize]);
-        let (_bytes, buf) = self.reparse_point(&mut space)?;
+        let (bytes, buf) = self.reparse_point(&mut space)?;
         unsafe {
-            let (path_buffer, subst_off, subst_len, relative) = match (*buf).ReparseTag {
+            let invalid_reparse_data = || {
+                io::Error::from_raw_os_error(c::ERROR_INVALID_REPARSE_DATA as i32)
+            };
+            let bytes = bytes as usize;
+            let reparse_buffer_len = size_of::<c::REPARSE_DATA_BUFFER>();
+            if bytes < reparse_buffer_len || bytes > space.0.len() {
+                return Err(invalid_reparse_data());
+            }
+            let reparse_data_len = usize::from((*buf).ReparseDataLength);
+            if bytes - reparse_buffer_len < reparse_data_len {
+                return Err(invalid_reparse_data());
+            }
+            let (path_buffer, path_buffer_len, subst_off, subst_len, relative) = match (*buf).ReparseTag {
                 c::IO_REPARSE_TAG_SYMLINK => {
                     let info: *mut c::SYMBOLIC_LINK_REPARSE_BUFFER = (&raw mut (*buf).rest).cast();
+                    let path_buffer_offset =
+                        offset_of!(c::SYMBOLIC_LINK_REPARSE_BUFFER, PathBuffer);
+                    if reparse_data_len < path_buffer_offset {
+                        return Err(invalid_reparse_data());
+                    }
                     assert!(info.is_aligned());
                     (
                         (&raw mut (*info).PathBuffer).cast::<u16>(),
-                        (*info).SubstituteNameOffset / 2,
-                        (*info).SubstituteNameLength / 2,
+                        reparse_data_len - path_buffer_offset,
+                        (*info).SubstituteNameOffset,
+                        (*info).SubstituteNameLength,
                         (*info).Flags & c::SYMLINK_FLAG_RELATIVE != 0,
                     )
                 }
                 c::IO_REPARSE_TAG_MOUNT_POINT => {
                     let info: *mut c::MOUNT_POINT_REPARSE_BUFFER = (&raw mut (*buf).rest).cast();
+                    let path_buffer_offset = offset_of!(c::MOUNT_POINT_REPARSE_BUFFER, PathBuffer);
+                    if reparse_data_len < path_buffer_offset {
+                        return Err(invalid_reparse_data());
+                    }
                     assert!(info.is_aligned());
                     (
                         (&raw mut (*info).PathBuffer).cast::<u16>(),
-                        (*info).SubstituteNameOffset / 2,
-                        (*info).SubstituteNameLength / 2,
+                        reparse_data_len - path_buffer_offset,
+                        (*info).SubstituteNameOffset,
+                        (*info).SubstituteNameLength,
                         false,
                     )
                 }
@@ -753,8 +776,14 @@ fn readlink(&self) -> io::Result<PathBuf> {
                     ));
                 }
             };
-            let subst_ptr = path_buffer.add(subst_off.into());
-            let subst = slice::from_raw_parts_mut(subst_ptr, subst_len as usize);
+            let Some(subst_end) = usize::from(subst_off).checked_add(usize::from(subst_len)) else {
+                return Err(invalid_reparse_data());
+            };
+            if subst_off % 2 != 0 || subst_len % 2 != 0 || subst_end > path_buffer_len {
+                return Err(invalid_reparse_data());
+            }
+            let subst_ptr = path_buffer.add(usize::from(subst_off / 2));
+            let subst = slice::from_raw_parts_mut(subst_ptr, usize::from(subst_len / 2));
             // Absolute paths start with an NT internal namespace prefix `\??\`
             // We should not let it leak through.
             if !relative && subst.starts_with(&[92u16, 63u16, 63u16, 92u16]) {
```