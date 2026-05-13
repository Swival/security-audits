# Crafted Lockfile Offsets Create Misaligned Typed Slices

## Classification

Memory corruption, high severity, certain confidence.

## Affected Locations

`src/install/lockfile/Buffers.rs:148`

## Summary

`read_array<T>` parsed attacker-controlled lockfile `start_pos` and `end_pos` values, then constructed a typed slice from raw lockfile bytes without validating alignment or element-size divisibility. A crafted lockfile could make `start_pos` misaligned for `T`, causing undefined behavior when `core::slice::from_raw_parts` was used through `bun_core::ffi::slice`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim parses an attacker-controlled lockfile.

## Proof

A crafted binary lockfile can set serialized array descriptor offsets so that the bounds and ordering checks pass while the typed array start is misaligned.

Concrete reproduced path:

- Use an empty package table.
- Use an empty tree section whose descriptor sets `start=end=144`.
- Place a hoisted-dependencies descriptor at offset `144` with `start=161,end=165`.
- This passes the existing backward and bounds checks.
- It produces `byte_len=4`.
- `read_array::<DependencyID>` then reaches:

```rust
stream.buffer.as_ptr().add(161).cast::<u32>()
```

`bun_core::ffi::slice` is `core::slice::from_raw_parts`, whose contract requires the pointer to be aligned for `T`. A `Vec<u8>` buffer is mimalloc-backed and at least word-aligned, so `base + 161` is not 4-byte aligned for `DependencyID` or `PackageID`, and not 8-byte aligned for `bun_semver::ExternalString`.

The invalid typed slice is then copied by `to_vec()` at `src/install/lockfile/Buffers.rs:154`, reading typed elements from attacker-chosen bytes through a misaligned reference.

## Why This Is A Real Bug

Rust requires references and slices to be properly aligned for their element type. The prior checks only validated sentinel values, monotonic ordering, and buffer bounds. They did not prove that:

- `start_pos` satisfies `align_of::<T>()`.
- `byte_len` is divisible by `size_of::<T>()`.

Therefore an attacker-controlled lockfile could cause undefined behavior before later semantic parsing had a chance to reject the file.

## Fix Requirement

Reject corrupt lockfiles when either condition is true:

- `start_pos` is not aligned to `align_of::<T>()`.
- `end_pos - start_pos` is not divisible by `size_of::<T>()`.

The rejection must occur before constructing any typed slice.

## Patch Rationale

The patch imports `align_of` and adds validation immediately after computing `byte_len`, before `stream.pos` is advanced and before the unsafe slice construction.

```rust
if start_pos % align_of::<T>() as u64 != 0 || byte_len % size_of::<T>() as u64 != 0 {
    return Err(bun_core::err!("CorruptLockfile"));
}
```

This converts malformed serialized array descriptors into `CorruptLockfile` errors and restores the safety preconditions claimed by the existing unsafe block.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/Buffers.rs b/src/install/lockfile/Buffers.rs
index 71077731b5..183f813da6 100644
--- a/src/install/lockfile/Buffers.rs
+++ b/src/install/lockfile/Buffers.rs
@@ -1,4 +1,4 @@
-use core::mem::size_of;
+use core::mem::{align_of, size_of};
 
 use bun_collections::DynamicBitSet as Bitset;
 use bun_core::Output;
@@ -147,6 +147,10 @@ pub fn read_array<T: Copy>(stream: &mut Stream) -> Result<Vec<T>, bun_core::Erro
     }
 
     let byte_len = end_pos - start_pos;
+    if start_pos % align_of::<T>() as u64 != 0 || byte_len % size_of::<T>() as u64 != 0 {
+        return Err(bun_core::err!("CorruptLockfile"));
+    }
+
     stream.pos = end_pos as usize;
 
     if byte_len == 0 {
```