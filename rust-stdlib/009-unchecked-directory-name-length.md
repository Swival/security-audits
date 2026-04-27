# unchecked directory name length

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/fs/windows.rs:1007`

## Summary

`DirBuffIter::next` trusted `FILE_ID_BOTH_DIR_INFO.FileNameLength` returned by `GetFileInformationByHandleEx` without checking that the trailing `FileName` bytes fit inside the current directory-entry record or the 1024-byte `DirBuff`.

A malformed filesystem provider could report an excessive `FileNameLength`, causing `from_maybe_unaligned` to create or read a `u16` slice beyond initialized directory-entry data. The reachable safe API path is Windows recursive directory removal through `remove_dir_all_iterative`, `fill_dir_buff`, and `DirBuffIter`.

## Provenance

Verified and reproduced from Swival Security Scanner evidence: https://swival.dev

Confidence: certain.

## Preconditions

- Target is Windows code in `library/std/src/sys/fs/windows.rs`.
- Directory enumeration uses `GetFileInformationByHandleEx` with `FILE_ID_BOTH_DIR_INFO`.
- The filesystem, redirector, or filesystem provider returns malformed directory information.
- The malformed entry has a `FileNameLength` that exceeds the bytes remaining in the current record or buffer.

## Proof

Directory entry data is written by `GetFileInformationByHandleEx` into `DirBuff`, whose capacity is 1024 bytes.

`DirBuffIter::next` reads the following fields from the returned buffer using unaligned loads:

- `NextEntryOffset`
- `FileNameLength`
- `FileAttributes`

Before the patch, it then called:

```rust
from_maybe_unaligned(
    (&raw const (*info).FileName).cast::<u16>(),
    length / size_of::<u16>(),
)
```

No validation ensured:

- `offset_of!(FILE_ID_BOTH_DIR_INFO, FileName) + FileNameLength <= entry_len`
- `NextEntryOffset <= remaining buffer length`
- `FileNameLength` is an even UTF-16 byte length

Concrete reproduced trigger:

- First returned record has `NextEntryOffset = 0`
- `FileNameLength = 2048`
- `DirBuff` total size is 1024 bytes

This makes the iterator request a 1024-element `u16` filename starting at the trailing `FileName` field, exceeding the backing buffer and causing an out-of-bounds read / Rust UB from a safe API path.

## Why This Is A Real Bug

The unsafe block relied on the OS/filesystem provider contract that `FileNameLength` describes initialized bytes inside the returned entry. That assumption is not enforced locally.

Rust standard library unsafe code must preserve memory safety even when external OS-facing data is malformed unless the safety contract explicitly requires trusted input. Here, a buggy or malicious filesystem/redirector can provide malformed directory information, and safe Rust code can reach the vulnerable iterator through recursive directory removal.

The impact is an out-of-bounds read and undefined behavior, not merely a logical parsing error.

## Fix Requirement

Validate directory-entry bounds before reading the filename:

- Ensure the fixed header reaches `FileName`.
- Derive the current entry length from `NextEntryOffset` or remaining buffer length.
- Reject entries whose `NextEntryOffset` exceeds the remaining buffer.
- Reject entries shorter than the `FileName` offset.
- Reject odd `FileNameLength` values.
- Reject names where `FileNameLength > entry_len - FileNameOffset`.

## Patch Rationale

The patch adds defensive bounds checks in `DirBuffIter::next` before calling `from_maybe_unaligned`.

It computes:

```rust
let name_offset = offset_of!(c::FILE_ID_BOTH_DIR_INFO, FileName);
let entry_len = if next_entry == 0 { buffer.len() } else { next_entry };
```

Then it stops iteration on malformed records where:

- the remaining buffer is smaller than the name offset,
- `entry_len` exceeds the remaining buffer,
- `entry_len` is smaller than the name offset,
- `FileNameLength` is not divisible by `size_of::<u16>()`,
- `FileNameLength` exceeds the bytes available after `FileName`.

This ensures `from_maybe_unaligned` only receives a length bounded by the initialized current entry.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/windows.rs b/library/std/src/sys/fs/windows.rs
index 74854cdeb49..8041f0e9ca7 100644
--- a/library/std/src/sys/fs/windows.rs
+++ b/library/std/src/sys/fs/windows.rs
@@ -969,8 +969,24 @@ fn next(&mut self) -> Option<Self::Item> {
             // it does not seem that reality is so kind, and assuming this
             // caused crashes in some cases (https://github.com/rust-lang/rust/issues/104530)
             // presumably, this can be blamed on buggy filesystem drivers, but who knows.
+            let name_offset = offset_of!(c::FILE_ID_BOTH_DIR_INFO, FileName);
+            if buffer.len() < name_offset {
+                self.buffer = None;
+                return None;
+            }
+
             let next_entry = (&raw const (*info).NextEntryOffset).read_unaligned() as usize;
             let length = (&raw const (*info).FileNameLength).read_unaligned() as usize;
+            let entry_len = if next_entry == 0 { buffer.len() } else { next_entry };
+            if entry_len > buffer.len()
+                || entry_len < name_offset
+                || length % size_of::<u16>() != 0
+                || length > entry_len - name_offset
+            {
+                self.buffer = None;
+                return None;
+            }
+
             let attrs = (&raw const (*info).FileAttributes).read_unaligned();
             let name = from_maybe_unaligned(
                 (&raw const (*info).FileName).cast::<u16>(),
```