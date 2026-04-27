# Unchecked Parameter Length Creates Static Slice

## Classification

High severity trust-boundary violation.

Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/xous/params.rs:136`

## Summary

`ApplicationParameters::new_from_ptr` trusted the loader-supplied `data_length` field when constructing a `&'static [u8]` from a raw pointer. A malicious or malformed loader parameter block could advertise a length larger than the mapped backing block, causing immediate Rust slice validity violation and later out-of-bounds reads during argument or environment parsing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with a harness that mirrored the committed logic and placed a valid `AppP` header at the end of a readable page with an oversized `data_length`.

## Preconditions

- The loader passes a non-null parameter pointer.
- The pointed data begins with valid `AppP` magic.
- The main block length is `8`.
- The loader-controlled `data_length` is at least `16`.
- The loader-controlled `data_length` exceeds the trusted mapped parameter block size.

## Proof

`set` stores the loader-controlled pointer in `PARAMS`, and `get` later calls `ApplicationParameters::new_from_ptr`.

`new_from_ptr` reads:

- magic from `data`
- `block_length` from `data + 4`
- `data_length` from `data + 8`
- `entries` from `data + 12`

Before the patch, it only rejected values where:

```rust
data_length < 16 || magic != PARAMS_MAGIC || block_length != 8
```

It then constructed:

```rust
let data = unsafe { slice::from_raw_parts(data, data_length) };
```

A reproducer with a valid 16-byte `AppP` header at the end of a readable page and `data_length = 32` was accepted. The function produced a 32-byte static slice even though the backing allocation did not contain 32 readable bytes. Iteration then attempted to read the next block header from an unmapped guard page and faulted.

The invalid slice is reachable through normal APIs because `library/std/src/sys/args/xous.rs:5` and `library/std/src/sys/env/xous.rs:15` call `params::get()` before iterating the returned parameters.

## Why This Is A Real Bug

`slice::from_raw_parts` requires the entire pointer range to be valid for reads for the lifetime of the returned slice. That requirement is violated as soon as `new_from_ptr` constructs a `&'static [u8]` over a loader-declared length that exceeds the actual mapped parameter block.

The iterator bounds checks only compare against `self.data.len()`, which is derived from the untrusted length. They cannot protect against a slice that was invalid at construction time.

Impact includes memory-safety undefined behavior, out-of-bounds reads, and process faults during argument or environment parsing.

## Fix Requirement

Validate `data_length` against a trusted maximum mapped parameter block size before constructing the static slice.

## Patch Rationale

The patch introduces:

```rust
const PARAMS_BLOCK_SIZE: usize = 4096;
```

and rejects oversized lengths before `slice::from_raw_parts`:

```rust
if data_length < 16
    || data_length > PARAMS_BLOCK_SIZE
    || magic != PARAMS_MAGIC
    || block_length != 8
{
    return None;
}
```

This ensures the constructed `&'static [u8]` cannot exceed the trusted Xous parameter block mapping size. Invalid oversized loader input is rejected before any static slice is created from it.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/xous/params.rs b/library/std/src/sys/pal/xous/params.rs
index d6f671e9a6b..84f34cf3cc9 100644
--- a/library/std/src/sys/pal/xous/params.rs
+++ b/library/std/src/sys/pal/xous/params.rs
@@ -105,6 +105,8 @@ pub(crate) fn get() -> Option<ApplicationParameters> {
 /// Magic number indicating the loader has passed application parameters
 const PARAMS_MAGIC: [u8; 4] = *b"AppP";
 
+const PARAMS_BLOCK_SIZE: usize = 4096;
+
 pub(crate) struct ApplicationParameters {
     data: &'static [u8],
     offset: usize,
@@ -129,7 +131,11 @@ unsafe fn new_from_ptr(data: *const u8) -> Option<ApplicationParameters> {
         };
 
         // Check for the main header
-        if data_length < 16 || magic != PARAMS_MAGIC || block_length != 8 {
+        if data_length < 16
+            || data_length > PARAMS_BLOCK_SIZE
+            || magic != PARAMS_MAGIC
+            || block_length != 8
+        {
             return None;
         }
```