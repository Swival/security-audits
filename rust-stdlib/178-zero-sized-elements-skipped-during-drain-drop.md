# Zero-Sized Elements Skipped During Drain Drop

## Classification

Resource lifecycle bug, medium severity.

Confidence: certain.

## Affected Locations

`library/core/src/array/drain.rs:101`

## Summary

`Drain` takes drop responsibility for an input array wrapped in `ManuallyDrop<[T; N]>`, but its cleanup path skipped zero-sized types entirely.

For non-ZSTs, `Drain::call_mut` advances `ptr` before invoking `f`, so `Drop` can later drop the unconsumed tail. For ZSTs, `Drain::call_mut` conjured values with `conjure_zst::<T>()` and did not track how many elements were consumed. `Drain::drop` then guarded all cleanup behind `if !T::IS_ZST`, so any remaining ZST elements with `Drop` were never destroyed when `Drain` was dropped early.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The issue was verified against `library/core/src/array/drain.rs` and reproduced with a zero-sized `Drop` type whose destructor increments an atomic counter.

## Preconditions

- `T` is zero-sized.
- `T` implements `Drop`.
- `Drain` is dropped before all `N` calls complete.
- Early drop is reachable through panic in the mapping closure or a short-circuiting caller such as `try_map`.

## Proof

The affected flow is:

- `Drain::new` receives `&mut ManuallyDrop<[T; N]>`, preventing the original array from being automatically dropped and transferring cleanup responsibility to `Drain`.
- For ZSTs, `Drain::call_mut` returns a conjured `T` using `conjure_zst::<T>()`.
- The ZST path did not advance `ptr` and did not maintain any consumed-element count.
- `Drain::drop` only dropped remaining elements inside `if !T::IS_ZST`.
- Therefore, when the drain was dropped early, remaining original ZST elements were skipped.

Runtime reproduction:

- A local PoC used `[Z; 4].map(|_| panic!())`.
- `Z` was a zero-sized type implementing `Drop`.
- `Drop` incremented an atomic counter.
- Observed output: `panicked=true drops=1`.
- Expected destructor count: `4`.
- Result: `3` ZST elements leaked their destructor execution.

## Why This Is A Real Bug

This is a real lifecycle bug because ownership of the array’s destruction is explicitly transferred away from the original array by `ManuallyDrop`, but `Drain` failed to perform equivalent cleanup for unconsumed ZST elements.

Zero-sized types can still implement `Drop`, and their destructors can perform observable work such as releasing resources, updating counters, unregistering state, or running other RAII cleanup. Skipping those destructors changes program behavior and violates Rust’s drop semantics for owned values.

The observed destructor count mismatch confirms the bug is reachable and not theoretical.

## Fix Requirement

The implementation must track how many ZST elements have already been moved out and must drop the remaining ZST elements when `Drain` is dropped.

Specifically:

- Add consumed-element state for ZST drains.
- Increment that state before invoking `f`, matching the non-ZST panic-safety pattern.
- In `Drop`, compute the remaining length for both ZST and non-ZST cases.
- Always call `drop_in_place` on the remaining slice, including for ZSTs.

## Patch Rationale

The patch adds an `idx: usize` field to `Drain` and initializes it to `0`.

For ZSTs, `call_mut` now increments `idx` before invoking the user closure. This mirrors the non-ZST path, where `ptr` is advanced before calling `f`, ensuring that if `f` panics, the element currently being processed is considered moved out and only the remaining elements are dropped.

`Drop` now computes:

- `N - self.idx` for ZSTs.
- `self.end.offset_from_unsigned(self.ptr.as_ptr())` for non-ZSTs.

It then constructs a slice with that length and calls `drop_in_place` unconditionally. This preserves the existing non-ZST behavior while adding the missing ZST cleanup path.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/array/drain.rs b/library/core/src/array/drain.rs
index 17792dca583..29a4731c0e5 100644
--- a/library/core/src/array/drain.rs
+++ b/library/core/src/array/drain.rs
@@ -25,7 +25,7 @@ impl<'l, 'f, T, U, const N: usize, F: FnMut(T) -> U> Drain<'l, 'f, T, N, F> {
         // for direct pointer equality with `ptr` to check if the drainer is done.
         unsafe {
             let end = if T::IS_ZST { null_mut() } else { ptr.as_ptr().add(N) };
-            Self { ptr, end, f, l: PhantomData }
+            Self { ptr, end, f, idx: 0, l: PhantomData }
         }
     }
 }
@@ -43,6 +43,8 @@ pub(super) struct Drain<'l, 'f, T, const N: usize, F> {
     /// For non-ZSTs, the non-null pointer to the past-the-end element.
     /// For ZSTs, this is null.
     end: *mut T,
+    /// Number of ZST elements already moved out.
+    idx: usize,
 
     f: &'f mut F,
     l: PhantomData<&'l mut [T; N]>,
@@ -73,6 +75,8 @@ extern "rust-call" fn call_mut(
         (_ /* ignore argument */,): (usize,),
     ) -> Self::Output {
         if T::IS_ZST {
+            // increment before moving; if `f` panics, we drop the rest.
+            self.idx += 1;
             // its UB to call this more than N times, so returning more ZSTs is valid.
             // SAFETY: its a ZST? we conjur.
             (self.f)(unsafe { conjure_zst::<T>() })
@@ -90,18 +94,16 @@ extern "rust-call" fn call_mut(
 #[unstable(feature = "array_try_map", issue = "79711")]
 impl<T: [const] Destruct, const N: usize, F> const Drop for Drain<'_, '_, T, N, F> {
     fn drop(&mut self) {
-        if !T::IS_ZST {
-            // SAFETY: we cant read more than N elements
-            let slice = unsafe {
-                from_raw_parts_mut::<[T]>(
-                    self.ptr.as_ptr(),
-                    // SAFETY: `start <= end`
-                    self.end.offset_from_unsigned(self.ptr.as_ptr()),
-                )
-            };
+        let len = if T::IS_ZST {
+            N - self.idx
+        } else {
+            // SAFETY: `start <= end`
+            unsafe { self.end.offset_from_unsigned(self.ptr.as_ptr()) }
+        };
+        // SAFETY: we cant read more than N elements
+        let slice = unsafe { from_raw_parts_mut::<[T]>(self.ptr.as_ptr(), len) };
 
-            // SAFETY: By the type invariant, we're allowed to drop all these. (we own it, after all)
-            unsafe { drop_in_place(slice) }
-        }
+        // SAFETY: By the type invariant, we're allowed to drop all these. (we own it, after all)
+        unsafe { drop_in_place(slice) }
     }
 }
```