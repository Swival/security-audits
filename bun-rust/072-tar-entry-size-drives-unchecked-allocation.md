# tar entry size drives unchecked allocation

## Classification

- Type: denial of service
- Severity: medium
- Confidence: certain

## Affected Locations

- `src/libarchive/lib.rs:876`
- `src/libarchive/lib.rs:902`
- `src/libarchive/lib.rs:909`
- Reachable call sites: `src/runtime/cli/publish_command.rs:265`
- Reachable call sites: `src/runtime/cli/publish_command.rs:280`

## Summary

`IteratorEntry::read_entry_data` trusted the tar header entry size and used it directly as a `Vec` allocation length. It rejected only negative sizes, so a malicious tarball could declare an enormous positive size and force memory exhaustion or allocator abort before any archive payload data was read.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Status: reproduced and patched

## Preconditions

- Caller reads entry data through `IteratorEntry::read_entry_data`.
- Attacker can provide a tarball consumed by this iterator path.
- The malicious entry reaches the data-read path after archive header parsing.

## Proof

The reproduced path showed `publish_command.rs` calls `entry.read_entry_data(iter.archive)?` after archive iteration.

A malicious tar entry such as `package/package.json` with file type `File` and an enormous positive tar size can pass the name stripping and top-level checks, then reach `IteratorEntry::read_entry_data`.

Before the patch, the function did:

```rust
let size = self.entry().size();
if size < 0 {
    return Ok(Err(IteratorError {
        archive,
        message: b"invalid archive entry size",
    }));
}
let mut buf = vec![0u8; usize::try_from(size).expect("int cast")];
```

The allocation occurred before:

```rust
let read = unsafe { &*archive }.read_data(&mut buf);
```

Therefore the archive did not need to contain the declared amount of data. The attacker-controlled tar header size alone could drive a large allocation.

## Why This Is A Real Bug

- The size comes from `archive_entry_size`, which is controlled by the tar header.
- The code rejected only `size < 0`, not excessively large positive values.
- `vec![0u8; size]` eagerly allocates and zero-fills the requested capacity.
- Allocation happens before `archive.read_data`, so payload truncation or short reads do not prevent the memory pressure.
- The reproduced publish path confirms this is reachable through normal archive processing.

## Fix Requirement

Cap the entry size before allocation and return an archive iterator error when the declared size exceeds the allowed maximum.

## Patch Rationale

The patch adds a fixed maximum for entry data read through `IteratorEntry::read_entry_data`:

```rust
const MAX_ENTRY_DATA_SIZE: i64 = 16 * 1024 * 1024;
if size < 0 || size > MAX_ENTRY_DATA_SIZE {
    return Ok(Err(IteratorError {
        archive,
        message: b"invalid archive entry size",
    }));
}
```

This preserves the existing error behavior for invalid sizes while preventing attacker-controlled large positive sizes from reaching `vec![0u8; ...]`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/libarchive/lib.rs b/src/libarchive/lib.rs
index 28c57763cc..648eab7346 100644
--- a/src/libarchive/lib.rs
+++ b/src/libarchive/lib.rs
@@ -900,7 +900,8 @@ pub mod lib {
             archive: *mut Archive,
         ) -> core::result::Result<IterResult<Vec<u8>>, bun_core::OOM> {
             let size = self.entry().size();
-            if size < 0 {
+            const MAX_ENTRY_DATA_SIZE: i64 = 16 * 1024 * 1024;
+            if size < 0 || size > MAX_ENTRY_DATA_SIZE {
                 return Ok(Err(IteratorError {
                     archive,
                     message: b"invalid archive entry size",
```