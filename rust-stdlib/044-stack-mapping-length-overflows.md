# stack mapping length overflows

## Classification

Medium severity validation gap.

Confidence: certain.

## Affected Locations

`library/std/src/sys/thread/xous.rs:37`

## Summary

`Thread::new` computes the Xous stack mapping length as `GUARD_PAGE_SIZE + stack_size + GUARD_PAGE_SIZE` without overflow checking. A page-aligned stack size near `usize::MAX` bypasses the existing rounding branch, wraps the mapping length, and allows `map_memory` to allocate a much smaller region than required for the requested stack plus guard pages.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was locally reproduced and patched.

## Preconditions

- Caller requests a page-aligned stack size near `usize::MAX`.
- Overflow checks are disabled, as in optimized Rust builds.
- The request reaches unsafe `Thread::new`, used by thread spawning.

## Proof

`stack` is assigned through `stack_size = max(stack, MIN_STACK_SIZE)`. If `stack_size` is already page-aligned, the rounding block is skipped and no checked arithmetic runs.

For `stack_size = usize::MAX & !4095`:

- `GUARD_PAGE_SIZE + stack_size + GUARD_PAGE_SIZE` wraps to `0x1000`.
- `map_memory` receives a one-page mapping length instead of the huge requested stack plus two guard pages.
- `(GUARD_PAGE_SIZE + stack_size)` wraps to `0`.
- The second guard update targets the wrong range.
- The stack slice `stack_plus_guard_pages[GUARD_PAGE_SIZE..(stack_size + GUARD_PAGE_SIZE)]` becomes `[4096..0]` and panics before `create_thread`.

A local Rust reproduction compiled with `-C overflow-checks=off` confirmed the wrapped mapped length is `0x1000` and the slice construction panics.

## Why This Is A Real Bug

The code accepts an invalid stack size that cannot be represented with both guard pages, then violates its own allocation invariant by mapping too little memory. Safe thread spawning can be driven into panic or abort behavior instead of returning an `io::Error`.

The bug is not only theoretical arithmetic overflow: the wrapped value is passed to `map_memory`, and later slice/index calculations observe the corrupted size relationship.

## Fix Requirement

The total mapping length must be computed with checked addition for both guard pages. If either addition overflows, `Thread::new` must reject the request with an error before calling `map_memory`.

## Patch Rationale

The patch introduces `mapped_memory_length`:

```rust
let mapped_memory_length = GUARD_PAGE_SIZE
    .checked_add(stack_size)
    .and_then(|size| size.checked_add(GUARD_PAGE_SIZE))
    .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "invalid stack size"))?;
```

This preserves existing behavior for valid stack sizes while rejecting impossible stack requests before allocation. `map_memory` now receives the validated `mapped_memory_length`, so the allocation size remains consistent with the requested stack and guard pages.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread/xous.rs b/library/std/src/sys/thread/xous.rs
index 208d43bb2c0..49b2752e59e 100644
--- a/library/std/src/sys/thread/xous.rs
+++ b/library/std/src/sys/thread/xous.rs
@@ -28,6 +28,11 @@ pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
             stack_size = (stack_size + 4095) & !4095;
         }
 
+        let mapped_memory_length = GUARD_PAGE_SIZE
+            .checked_add(stack_size)
+            .and_then(|size| size.checked_add(GUARD_PAGE_SIZE))
+            .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "invalid stack size"))?;
+
         // Allocate the whole thing, then divide it up after the fact. This ensures that
         // even if there's a context switch during this function, the whole stack plus
         // guard pages will remain contiguous.
@@ -35,7 +40,7 @@ pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
             map_memory(
                 None,
                 None,
-                GUARD_PAGE_SIZE + stack_size + GUARD_PAGE_SIZE,
+                mapped_memory_length,
                 MemoryFlags::R | MemoryFlags::W | MemoryFlags::X,
             )
         }
```