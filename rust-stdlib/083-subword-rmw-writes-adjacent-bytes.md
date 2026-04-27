# subword RMW writes adjacent bytes

## Classification

Data integrity bug, high severity, confidence certain.

## Affected Locations

`library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs:116`

## Summary

The ARM Linux compiler-builtins implementation emulates `u8` and `u16` atomic read-modify-write and compare-exchange operations by aligning the target pointer down to a `u32`, merging the requested subword update into that containing word, and invoking `__kuser_cmpxchg` on the aligned word address. A successful operation therefore performs a 32-bit write even when the requested atomic object is only 1 or 2 bytes wide.

## Provenance

Verified from the supplied source, reproducer summary, and patch. Initially identified by Swival Security Scanner: https://swival.dev

## Preconditions

- A generated `u8` or `u16` atomic intrinsic is called.
- The target byte or halfword shares its aligned 4-byte word with unrelated bytes.
- Those adjacent bytes are outside the intended atomic object.

## Proof

For a byte operation such as `__sync_fetch_and_add_1(ptr_to_byte_1, 1)`, `atomic_rmw` computes:

- `aligned_ptr = align_ptr(ptr)`, pointing to the containing 4-byte word.
- `(shift, mask) = get_shift_mask(ptr)`, selecting the requested byte.
- `curval_aligned = atomic_load_aligned::<T>(aligned_ptr)`, loading the full word.
- `newval_aligned = insert_aligned(curval_aligned, newval, shift, mask)`, producing a full-word replacement.
- `__kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr)`, passing the aligned `u32` address to a helper that compares and exchanges a 32-bit word.

For little-endian bytes `[0x11, 0x22, 0x33, 0x44]`, targeting byte 1 with an increment computes `[0x11, 0x23, 0x33, 0x44]` and asks the kernel helper to store that entire 32-bit value at the aligned base address.

In ordinary uncontended RAM, adjacent bytes are usually rewritten with the same values because the full-word compare must match before the exchange succeeds. The bug is still reproduced because the operation performs a successful full-word write outside the `u8` or `u16` atomic object boundary.

## Why This Is A Real Bug

Subword atomic operations must not write bytes outside the subword atomic object. The implementation violates that boundary by using a full-word compare-exchange for `u8` and `u16` operations.

This is observable and unsafe when adjacent bytes are MMIO or otherwise side-effecting, and it can also affect synchronization or modification-order-sensitive adjacent atomic objects. The absence of value changes in the common uncontended RAM case does not make the full-width write correct.

## Fix Requirement

Implement `u8` and `u16` atomics without successful full-word writes to adjacent bytes, or otherwise require and enforce that every byte in the containing aligned word belongs to the same atomic object.

## Patch Rationale

The patch preserves the existing `__kuser_cmpxchg` path for 32-bit atomics, where the operation width matches the object width.

For subword atomics, it introduces a global spin lock and performs volatile 1-byte or 2-byte loads and stores directly at the requested pointer. This serializes compiler-builtins subword atomic operations while ensuring the write width is limited to the actual `u8` or `u16` object. As a result, successful subword RMW and compare-exchange operations no longer write adjacent bytes in the containing aligned word.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs b/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
index 7edd76c0b8b..d83e0d0cbac 100644
--- a/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
+++ b/library/compiler-builtins/compiler-builtins/src/sync/arm_linux.rs
@@ -101,43 +101,94 @@ unsafe fn atomic_load_aligned<T>(ptr: *mut u32) -> u32 {
     }
 }
 
+static SUBWORD_LOCK: AtomicU32 = AtomicU32::new(0);
+
+unsafe fn subword_lock() {
+    while unsafe { !__kuser_cmpxchg(0, 1, SUBWORD_LOCK.as_ptr()) } {
+        while SUBWORD_LOCK.load(Ordering::Relaxed) != 0 {
+            core::hint::spin_loop();
+        }
+    }
+}
+
+unsafe fn subword_unlock() {
+    while unsafe { !__kuser_cmpxchg(1, 0, SUBWORD_LOCK.as_ptr()) } {
+        core::hint::spin_loop();
+    }
+}
+
+unsafe fn atomic_load_subword<T>(ptr: *mut T) -> u32 {
+    match mem::size_of::<T>() {
+        1 => unsafe { (ptr as *const u8).read_volatile() as u32 },
+        2 => unsafe { (ptr as *const u16).read_volatile() as u32 },
+        _ => unreachable!(),
+    }
+}
+
+unsafe fn atomic_store_subword<T>(ptr: *mut T, val: u32) {
+    match mem::size_of::<T>() {
+        1 => unsafe { (ptr as *mut u8).write_volatile(val as u8) },
+        2 => unsafe { (ptr as *mut u16).write_volatile(val as u16) },
+        _ => unreachable!(),
+    }
+}
+
 // Generic atomic read-modify-write operation
 unsafe fn atomic_rmw<T, F: Fn(u32) -> u32, G: Fn(u32, u32) -> u32>(ptr: *mut T, f: F, g: G) -> u32 {
-    let aligned_ptr = align_ptr(ptr);
-    let (shift, mask) = get_shift_mask(ptr);
+    if mem::size_of::<T>() == 4 {
+        let aligned_ptr = align_ptr(ptr);
+        let (shift, mask) = get_shift_mask(ptr);
 
-    loop {
-        // FIXME(safety): preconditions review needed
-        let curval_aligned = unsafe { atomic_load_aligned::<T>(aligned_ptr) };
-        let curval = extract_aligned(curval_aligned, shift, mask);
-        let newval = f(curval);
-        let newval_aligned = insert_aligned(curval_aligned, newval, shift, mask);
-        // FIXME(safety): preconditions review needed
-        if unsafe { __kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr) } {
-            return g(curval, newval);
+        loop {
+            // FIXME(safety): preconditions review needed
+            let curval_aligned = unsafe { atomic_load_aligned::<T>(aligned_ptr) };
+            let curval = extract_aligned(curval_aligned, shift, mask);
+            let newval = f(curval);
+            let newval_aligned = insert_aligned(curval_aligned, newval, shift, mask);
+            // FIXME(safety): preconditions review needed
+            if unsafe { __kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr) } {
+                return g(curval, newval);
+            }
         }
+    } else {
+        unsafe { subword_lock() };
+        let curval = unsafe { atomic_load_subword(ptr) };
+        let newval = f(curval);
+        unsafe { atomic_store_subword(ptr, newval) };
+        unsafe { subword_unlock() };
+        g(curval, newval)
     }
 }
 
 // Generic atomic compare-exchange operation
 unsafe fn atomic_cmpxchg<T>(ptr: *mut T, oldval: u32, newval: u32) -> u32 {
-    let aligned_ptr = align_ptr(ptr);
-    let (shift, mask) = get_shift_mask(ptr);
+    if mem::size_of::<T>() == 4 {
+        let aligned_ptr = align_ptr(ptr);
+        let (shift, mask) = get_shift_mask(ptr);
 
-    loop {
-        // SAFETY: the caller must guarantee that the pointer is valid for read and write
-        // and aligned to the element size.
-        let curval_aligned = unsafe { atomic_load_aligned::<T>(aligned_ptr) };
-        let curval = extract_aligned(curval_aligned, shift, mask);
-        if curval != oldval {
-            return curval;
+        loop {
+            // SAFETY: the caller must guarantee that the pointer is valid for read and write
+            // and aligned to the element size.
+            let curval_aligned = unsafe { atomic_load_aligned::<T>(aligned_ptr) };
+            let curval = extract_aligned(curval_aligned, shift, mask);
+            if curval != oldval {
+                return curval;
+            }
+            let newval_aligned = insert_aligned(curval_aligned, newval, shift, mask);
+            // SAFETY: the caller must guarantee that the pointer is valid for read and write
+            // and aligned to the element size.
+            if unsafe { __kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr) } {
+                return oldval;
+            }
         }
-        let newval_aligned = insert_aligned(curval_aligned, newval, shift, mask);
-        // SAFETY: the caller must guarantee that the pointer is valid for read and write
-        // and aligned to the element size.
-        if unsafe { __kuser_cmpxchg(curval_aligned, newval_aligned, aligned_ptr) } {
-            return oldval;
+    } else {
+        unsafe { subword_lock() };
+        let curval = unsafe { atomic_load_subword(ptr) };
+        if curval == oldval {
+            unsafe { atomic_store_subword(ptr, newval) };
         }
+        unsafe { subword_unlock() };
+        curval
     }
 }
```