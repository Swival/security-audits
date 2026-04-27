# File Name Length Underflow

## Classification

Invariant violation. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/uefi/helpers.rs:827`

## Summary

`UefiBox<file::Info>::file_name_len` subtracts the fixed `file::Info<0>` header size from the firmware-provided `file::Info.size` field without validating that `size` is at least the header size. A malformed below-header `size` underflows in optimized builds, producing a huge filename length that is then used to construct an out-of-bounds UTF-16 slice.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A `UefiBox<file::Info>` contains a `file::Info` whose `size` field is smaller than `size_of::<file::Info<0>>()`.

## Proof

The reproduced path reaches `Directory::from_uefi`, which calls `file_name_from_uefi` at `library/std/src/sys/fs/uefi.rs:196`; that calls `info.file_name()` at `library/std/src/sys/fs/uefi.rs:902`.

`info.file_name()` calls `UefiBox<file::Info>::file_name_len`. Before the patch, `library/std/src/sys/pal/uefi/helpers.rs:833` computed:

```rust
(self.size() as usize - size_of::<file::Info<0>>()) / size_of::<u16>()
```

For a malformed `file::Info.size = 0`, the subtraction underflows in optimized builds and wraps to a very large `usize`. `library/std/src/sys/pal/uefi/helpers.rs:838` then passes that wrapped length to `slice::from_raw_parts` using the fixed `file_name` pointer.

Result: `file_name()` exposes an out-of-bounds slice. Subsequent UTF-16 conversion can read adjacent memory, crash, or invoke undefined behavior. Debug or overflow-checked builds would panic instead.

The mutable accessor is less directly reachable for this below-header case through current `with_file_name` logic, but it shares the same unsafe length calculation.

## Why This Is A Real Bug

The `size` field is read from a UEFI `file::Info` structure that may be firmware-provided or copied from firmware-provided data. The code assumes the field satisfies the `file::Info` layout invariant but does not enforce it before using the value in unsafe slice construction.

Rust slice creation requires the pointer and length to describe a valid allocation. A wrapped filename length violates that requirement immediately at `slice::from_raw_parts`, so this is not merely an incorrect filename parse; it is memory unsafety.

## Fix Requirement

Validate that `file::Info.size >= size_of::<file::Info<0>>()` before subtracting or using the derived filename length for slicing.

## Patch Rationale

The patch changes the subtraction to `saturating_sub`:

```rust
(self.size() as usize).saturating_sub(size_of::<file::Info<0>>()) / size_of::<u16>()
```

For valid structures, behavior is unchanged. For below-header structures, the derived filename length becomes `0` instead of wrapping to a huge value, so `file_name()` and `file_name_mut()` construct empty slices rather than out-of-bounds slices.

This directly enforces a safe lower bound at the only shared length derivation point.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/uefi/helpers.rs b/library/std/src/sys/pal/uefi/helpers.rs
index 9db72db6067..021f24528a7 100644
--- a/library/std/src/sys/pal/uefi/helpers.rs
+++ b/library/std/src/sys/pal/uefi/helpers.rs
@@ -830,7 +830,7 @@ fn set_size(&mut self, s: u64) {
 
     // Length of string (including NULL), not number of bytes.
     fn file_name_len(&self) -> usize {
-        (self.size() as usize - size_of::<file::Info<0>>()) / size_of::<u16>()
+        (self.size() as usize).saturating_sub(size_of::<file::Info<0>>()) / size_of::<u16>()
     }
 
     pub(crate) fn file_name(&self) -> &[u16] {
```