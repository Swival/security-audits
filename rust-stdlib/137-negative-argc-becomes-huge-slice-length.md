# Negative argc Becomes Huge Slice Length

## Classification

Validation gap; high severity; confidence certain.

## Affected Locations

`library/std/src/sys/args/sgx.rs:22`

## Summary

SGX argument initialization accepted negative `argc` values because it only rejected zero. The negative `isize` was then cast to `usize` and used as the element count for unsafe user-slice construction, turning malformed SGX entry arguments into a huge attacker-controlled length before Rust `main` runs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

SGX args initialization is called with `argc < 0`.

## Proof

`argc` enters `init(argc, argv)` at `library/std/src/sys/args/sgx.rs:19`.

The original guard only checked:

```rust
if argc != 0 {
```

Therefore, negative values passed validation and reached:

```rust
alloc::User::<[ByteBuffer]>::from_raw_parts(argv as _, argc as _)
```

At `library/std/src/sys/args/sgx.rs:22`, `argc as _` converts a negative `isize` to its two's-complement `usize` representation. `alloc::User::<[ByteBuffer]>::from_raw_parts` expects a valid element count at `library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:339`.

A practical trigger is an SGX `p2` value with the high bit set, such as `0x8000_0000_000f_4240`, which becomes a negative `isize` but casts back to a huge `usize`. In optimized builds, byte-size multiplication in `library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:340` can wrap to a smaller but still attacker-chosen slice length. The subsequent iterator pipeline at `library/std/src/sys/args/sgx.rs:23` then processes many user-controlled `ByteBuffer` entries.

## Why This Is A Real Bug

The unsafe slice-construction precondition is violated before argument copying begins. A malformed SGX entry can cause excessive iteration, excessive allocation, aborts, or invalid user-buffer processing during standard-library argument setup, before user code executes.

## Fix Requirement

Reject non-positive `argc` values before casting to `usize`, or otherwise validate the conversion with `usize::try_from(argc)`.

## Patch Rationale

The patch changes the guard from `argc != 0` to `argc > 0`.

This preserves the existing behavior for valid positive argument counts and empty argument lists, while excluding all negative counts before the unsafe cast and `from_raw_parts` call.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/args/sgx.rs b/library/std/src/sys/args/sgx.rs
index 6ff94f5681b..4793a035f47 100644
--- a/library/std/src/sys/args/sgx.rs
+++ b/library/std/src/sys/args/sgx.rs
@@ -18,7 +18,7 @@
 
 #[cfg_attr(test, allow(dead_code))]
 pub unsafe fn init(argc: isize, argv: *const *const u8) {
-    if argc != 0 {
+    if argc > 0 {
         let args = unsafe { alloc::User::<[ByteBuffer]>::from_raw_parts(argv as _, argc as _) };
         let args = args
             .iter()
```