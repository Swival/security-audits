# subword compare-exchange writes adjacent bytes

## Classification

Data integrity bug, high severity, certain confidence.

## Affected Locations

`library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs:138`

## Summary

The ARM Linux compare-exchange implementation routes `u8` and `u16` compare-exchange intrinsics through a helper that operates on an aligned `u32`. A successful subword compare-exchange therefore invokes `__kuser_cmpxchg` on the containing 32-bit word, not only on the requested byte or halfword. This violates the atomic object boundary and can write adjacent storage that the caller did not authorize.

## Provenance

Verified from the supplied source, reproducer reasoning, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A generated `__sync_*_compare_and_swap` intrinsic is called for a valid `u8` or `u16` atomic.
- The target is on this ARM Linux backend using `__kuser_cmpxchg`.
- The caller provides a pointer valid for the subword atomic object, not necessarily for writes to the full containing `u32`.

## Proof

`atomic_cmpxchg!` generates compare-exchange entry points for multiple integer widths. For subword types, the generated function calls:

```rust
unsafe { atomic_cmpxchg(ptr, oldval as u32, newval as u32) as $ty }
```

Inside `atomic_cmpxchg`, the pointer is rounded down to the containing word:

```rust
let aligned_ptr = align_ptr(ptr);
```

The current aligned word is loaded, the target lane is extracted, and the replacement value is inserted only into that lane:

```rust
let curval_aligned = unsafe { atomic_load_aligned::<T>(aligned_ptr) };
let curval = extract_aligned(curval_aligned, shift, mask);
let newval_aligned = insert_aligned(curval_aligned, newval, shift, mask);
```

However, the final compare-exchange is performed with:

```rust
__kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr)
```

`__kuser_cmpxchg` has the signature:

```rust
unsafe fn __kuser_cmpxchg(oldval: u32, newval: u32, ptr: *mut u32) -> bool
```

So the kernel helper compares and writes the full aligned `u32`.

Concrete little-endian example: for word bytes `[0x11, 0x22, 0x33, 0x44]`, a byte compare-exchange on the second byte from `0x22` to `0xaa` computes `newval_aligned = 0x4433aa11` and calls the helper on the base `u32*`. A successful operation writes the full four-byte word `[0x11, 0xaa, 0x33, 0x44]`, touching adjacent byte lanes outside the requested one-byte atomic.

## Why This Is A Real Bug

A byte or halfword compare-exchange must only write the atomic object supplied by the caller. This implementation performs a successful write to the full containing 32-bit word.

Although adjacent lanes are usually written back with their previously observed values in normal uncontended RAM, the operation still writes storage outside the atomic object. That storage may be a separate object, may not be valid for a full-word write under the caller’s contract, or may be side-effectful mapped memory. The generated subword compare-exchange therefore violates its required memory-access boundary.

## Fix Requirement

Subword compare-exchange must not be implemented using the full-word `__kuser_cmpxchg` helper on the containing `u32`.

Acceptable fixes are:

- Use true byte and halfword atomic compare-exchange helpers where available.
- Or do not emit subword compare-exchange intrinsics on this backend.

## Patch Rationale

The patch changes the `atomic_cmpxchg!` macro so it only emits an implementation for `u32`:

```diff
-    ($name:ident, $ty:ty) => {
+    ($name:ident, u32) => {
```

The emitted function now takes and returns `u32` directly:

```diff
-            pub unsafe extern "C" fn $name(ptr: *mut $ty, oldval: $ty, newval: $ty) -> $ty {
+            pub unsafe extern "C" fn $name(ptr: *mut u32, oldval: u32, newval: u32) -> u32 {
```

It also removes unnecessary casts:

```diff
-                unsafe { atomic_cmpxchg(ptr, oldval as u32, newval as u32) as $ty }
+                unsafe { atomic_cmpxchg(ptr, oldval, newval) }
```

Finally, the fallback macro arm suppresses generation for all other types:

```rust
($name:ident, $ty:ty) => {};
```

This prevents `u8` and `u16` compare-exchange symbols from being generated through the unsafe full-word path.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs b/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
index 7edd76c0b8b..f4e94e32786 100644
--- a/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
+++ b/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
@@ -167,15 +167,16 @@ macro_rules! atomic_rmw {
     };
 }
 macro_rules! atomic_cmpxchg {
-    ($name:ident, $ty:ty) => {
+    ($name:ident, u32) => {
         intrinsics! {
-            pub unsafe extern "C" fn $name(ptr: *mut $ty, oldval: $ty, newval: $ty) -> $ty {
+            pub unsafe extern "C" fn $name(ptr: *mut u32, oldval: u32, newval: u32) -> u32 {
                 // SAFETY: the caller must guarantee that the pointer is valid for read and write
                 // and aligned to the element size.
-                unsafe { atomic_cmpxchg(ptr, oldval as u32, newval as u32) as $ty }
+                unsafe { atomic_cmpxchg(ptr, oldval, newval) }
             }
         }
     };
+    ($name:ident, $ty:ty) => {};
 }
 
 include!("arm_thumb_shared.rs");
```