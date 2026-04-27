# Raw Slice Split Length Underflow

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/core/src/ptr/mut_ptr.rs:1263`

## Summary

`*mut [T]::split_at_mut_unchecked` accepted a caller-controlled `mid` greater than the raw slice metadata length. The function then computed `len - mid`, which underflowed and produced a malformed right raw slice with an impossible length.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The caller invokes `split_at_mut_unchecked` with `mid > self.len()`.

## Proof

`split_at_mut_unchecked` reads the raw slice metadata into `len`, obtains the data pointer, computes `ptr.add(mid)`, and constructs:

```rust
crate::ptr::slice_from_raw_parts_mut(tail, len - mid)
```

With `len = 3` and `mid = 4`, `len - mid` underflows on `usize`.

The reproduced nightly output showed:

```text
input_len=3 left_len=4 right_len=18446744073709551615
[10, 20, 30, 99, 50]
```

This demonstrates that `mid` propagates into both the left slice length and the right slice subtraction, and that the returned right raw slice can contain malformed metadata observable through safe raw-pointer `len()`.

## Why This Is A Real Bug

The method is public unsafe API, but its documented safety precondition only required `mid` to be in-bounds of the underlying allocation. That permits cases where `mid` is valid for `ptr.add(mid)` but greater than the raw slice metadata length.

In that state, the function returns raw slice metadata that does not describe the original slice split. Later unsafe conversion or use of the returned right slice can treat memory far beyond the allocation as part of the slice.

## Fix Requirement

Require `mid <= len` before computing the right slice length, or otherwise make the subtraction conditional on that precondition using checked or asserted unchecked arithmetic.

## Patch Rationale

The patch adds an unsafe precondition assertion:

```rust
ub_checks::assert_unsafe_precondition!(
    check_library_ub,
    "ptr::split_at_mut_unchecked requires the index to be within the slice",
    (mid: usize = mid, len: usize = len) => mid <= len,
);
```

This aligns the unchecked implementation with the invariant needed by `len - mid`: the split index must not exceed the raw slice length.

After asserting the invariant, the patch replaces ordinary subtraction with:

```rust
unsafe { intrinsics::unchecked_sub(len, mid) }
```

That makes the arithmetic contract explicit: the subtraction is only valid because the immediately preceding unsafe precondition establishes `mid <= len`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/ptr/mut_ptr.rs b/library/core/src/ptr/mut_ptr.rs
index 98b70a77fad..c88f4b72db0 100644
--- a/library/core/src/ptr/mut_ptr.rs
+++ b/library/core/src/ptr/mut_ptr.rs
@@ -1860,11 +1860,17 @@ pub unsafe fn split_at_mut_unchecked(self, mid: usize) -> (*mut [T], *mut [T]) {
         let len = self.len();
         let ptr = self.as_mut_ptr();
 
+        ub_checks::assert_unsafe_precondition!(
+            check_library_ub,
+            "ptr::split_at_mut_unchecked requires the index to be within the slice",
+            (mid: usize = mid, len: usize = len) => mid <= len,
+        );
+
         // SAFETY: Caller must pass a valid pointer and an index that is in-bounds.
         let tail = unsafe { ptr.add(mid) };
         (
             crate::ptr::slice_from_raw_parts_mut(ptr, mid),
-            crate::ptr::slice_from_raw_parts_mut(tail, len - mid),
+            crate::ptr::slice_from_raw_parts_mut(tail, unsafe { intrinsics::unchecked_sub(len, mid) }),
         )
     }
```