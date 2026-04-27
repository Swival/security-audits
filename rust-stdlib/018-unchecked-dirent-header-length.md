# unchecked dirent header length

## Classification

High-severity vulnerability: unchecked external directory-entry length causes unsafe out-of-bounds read in safe `std::fs::read_dir` iteration on Hermit.

Confidence: certain.

## Affected Locations

- `library/std/src/sys/fs/hermit.rs:200`
- `library/std/src/sys/fs/hermit.rs:194`
- `library/std/src/sys/fs/hermit.rs:532`

## Summary

`readdir` accepts any positive `getdents64` byte count and stores it as the directory buffer length. `ReadDir::next` then only checks whether `offset >= self.inner.dir.len()` before casting the current offset to `*const dirent64` and dereferencing it.

If `getdents64` returns a positive byte count smaller than `mem::size_of::<dirent64>()`, safe iteration of `std::fs::read_dir` can cause an unsafe read past the allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided affected source and reproducer evidence.

## Preconditions

- Target platform is Hermit.
- A caller iterates `std::fs::read_dir`.
- `hermit_abi::getdents64` returns a positive byte count smaller than a `dirent64` header, or otherwise returns a malformed record whose `d_reclen` is smaller than the header or larger than remaining buffer bytes.

## Proof

`readdir` reads raw directory bytes into `vec` using `hermit_abi::getdents64`.

On any positive `readlen`, it treats the call as successful and resizes the vector to that byte count:

```rust
if readlen > 0 {
    vec.resize(readlen.try_into().unwrap(), 0);
    break;
}
```

`ReadDir::next` only checks for end of buffer:

```rust
if offset >= self.inner.dir.len() {
    return None;
}
```

For a short positive buffer, such as length `1`, `offset == 0` passes that check. The next operation casts the buffer start to `*const dirent64` and dereferences it:

```rust
let dir = unsafe { &*(self.inner.dir.as_ptr().add(offset) as *const dirent64) };
```

That dereference requires a full valid `dirent64`, but the allocation may contain fewer bytes. The later `CStr::from_ptr` on `dir.d_name` further assumes the header and name area exist and are valid.

## Why This Is A Real Bug

This is reachable from safe Rust through `std::fs::read_dir` on Hermit. The unsafe block trusts externally supplied syscall data without first validating that enough bytes remain for a `dirent64` header.

The end-of-buffer check proves only that at least one byte may remain, not that a complete header exists. Therefore a positive short `getdents64` result can trigger undefined behavior through an out-of-bounds read. Practical outcomes include crashes, fabricated directory entries, invalid memory reads, or memory disclosure depending on allocator layout and returned bytes.

## Fix Requirement

Before each `dirent64` dereference:

- Verify that remaining bytes are at least `mem::size_of::<dirent64>()`.
- After reading the header, validate `d_reclen`.
- Reject entries where `d_reclen < mem::size_of::<dirent64>()`.
- Reject entries where `d_reclen > remaining`.
- Advance by the validated `d_reclen`.

## Patch Rationale

The patch adds a `remaining` calculation before the unsafe cast and rejects buffers too short to contain a complete `dirent64`. This prevents the original out-of-bounds header dereference.

After the header is safely available, the patch validates `d_reclen` before using it. This prevents malformed records from causing offset advancement outside the buffer or creating records shorter than their mandatory header.

Invalid directory data is returned as `ErrorKind::InvalidData`, preserving safe API behavior while refusing malformed syscall output.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/hermit.rs b/library/std/src/sys/fs/hermit.rs
index 5992766b5a4..74937689882 100644
--- a/library/std/src/sys/fs/hermit.rs
+++ b/library/std/src/sys/fs/hermit.rs
@@ -195,7 +195,16 @@ fn next(&mut self) -> Option<io::Result<DirEntry>> {
                 return None;
             }
 
+            let remaining = self.inner.dir.len() - offset;
+            if remaining < mem::size_of::<dirent64>() {
+                return Some(Err(io::const_error!(ErrorKind::InvalidData, "invalid directory entry")));
+            }
+
             let dir = unsafe { &*(self.inner.dir.as_ptr().add(offset) as *const dirent64) };
+            let reclen = usize::from(dir.d_reclen);
+            if reclen < mem::size_of::<dirent64>() || reclen > remaining {
+                return Some(Err(io::const_error!(ErrorKind::InvalidData, "invalid directory entry")));
+            }
 
             if counter == self.pos {
                 self.pos += 1;
@@ -219,7 +228,7 @@ fn next(&mut self) -> Option<io::Result<DirEntry>> {
             counter += 1;
 
             // move to the next dirent64, which is directly stored after the previous one
-            offset = offset + usize::from(dir.d_reclen);
+            offset = offset + reclen;
         }
     }
 }
```