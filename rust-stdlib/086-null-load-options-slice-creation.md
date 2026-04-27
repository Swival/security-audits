# null load_options slice creation

## Classification

Invariant violation; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/args/uefi.rs:29`

## Summary

UEFI argument parsing can call `crate::slice::from_raw_parts` with a null `load_options` pointer when `load_options_size` is positive and UTF-16-sized. The existing alignment check does not reject null because address `0` is aligned for `u16`, so slice creation violates Rust's non-null slice pointer invariant before the fallback path can run.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- UEFI `loaded_image` protocol is available.
- `loaded_image.load_options` is null.
- `loaded_image.load_options_size` is positive and an even number of bytes.

## Proof

`load_options_size` is read and validated only for UTF-16 byte length. A value such as `2` passes the size checks and becomes a slice length of `1`.

`load_options` is then cast to `*const u16`, and the code checks only:

```rust
if !lp_cmd_line.is_aligned() {
    return Args::new(lazy_current_exe());
}
```

A null pointer is considered aligned because pointer alignment is computed from the address, and address `0` satisfies `addr & (align - 1) == 0`.

Execution then reaches:

```rust
let lp_cmd_line = unsafe { crate::slice::from_raw_parts(lp_cmd_line, lp_size) };
```

`slice::from_raw_parts` requires the pointer to be aligned and non-null. With `load_options = null` and `load_options_size = 2`, the local reproducer observed:

```text
null is_aligned = true, len = 1
unsafe precondition(s) violated: slice::from_raw_parts requires the pointer to be aligned and non-null
```

## Why This Is A Real Bug

The state is inconsistent but representable by the UEFI loaded-image protocol: `load_options_size` can be positive while `load_options` is null. The current code handles malformed sizes and misalignment by falling back to `current_exe`, but it misses null. As a result, calls such as `std::env::args_os()` on UEFI can trigger undefined behavior during slice construction before parsing or fallback occurs.

## Fix Requirement

Return the existing fallback result when `load_options` is null, before calling `crate::slice::from_raw_parts`.

## Patch Rationale

The patch extends the existing pointer validity guard to reject null pointers as well as misaligned pointers:

```rust
if lp_cmd_line.is_null() || !lp_cmd_line.is_aligned() {
    return Args::new(lazy_current_exe());
}
```

This preserves the established fallback behavior for invalid command-line data and ensures `from_raw_parts` is called only with a non-null, aligned pointer and a previously validated UTF-16 element count.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/args/uefi.rs b/library/std/src/sys/args/uefi.rs
index edf6f6873f8..60fa6ab6aab 100644
--- a/library/std/src/sys/args/uefi.rs
+++ b/library/std/src/sys/args/uefi.rs
@@ -23,7 +23,7 @@ pub fn args() -> Args {
     let lp_size = lp_size / size_of::<u16>();
 
     let lp_cmd_line = unsafe { (*protocol.as_ptr()).load_options as *const u16 };
-    if !lp_cmd_line.is_aligned() {
+    if lp_cmd_line.is_null() || !lp_cmd_line.is_aligned() {
         return Args::new(lazy_current_exe());
     }
     let lp_cmd_line = unsafe { crate::slice::from_raw_parts(lp_cmd_line, lp_size) };
```