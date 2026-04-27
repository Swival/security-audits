# Stack Rounding Addition Overflows

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/thread/xous.rs:27`

## Summary

The Xous thread backend rounded requested stack sizes with `stack_size + 4095` before masking to a page boundary. For an unaligned `stack_size > usize::MAX - 4095`, this addition overflows. In wrapping builds the rounded stack size can become `0`; in overflow-checking builds it panics inside a safe thread-spawn path.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller supplies an unaligned thread stack size greater than `usize::MAX - 4095`.

## Proof

`Thread::new` receives the caller-controlled stack size and computes:

```rust
let mut stack_size = crate::cmp::max(stack, MIN_STACK_SIZE);

if (stack_size & 4095) != 0 {
    stack_size = (stack_size + 4095) & !4095;
}
```

For any unaligned value above `usize::MAX - 4095`, `stack_size + 4095` overflows.

With wrapping arithmetic, the sum wraps into `0..=4094`, and `& !4095` clears the low bits, producing `0`. That violates the intended invariant that rounding produces a page-aligned stack size at least as large as the requested size.

The zero stack size then propagates to:

- `map_memory(..., GUARD_PAGE_SIZE + stack_size + GUARD_PAGE_SIZE, ...)`, mapping only the two guard pages.
- `update_memory_flags(&mut stack_plus_guard_pages[0..GUARD_PAGE_SIZE], ...)`.
- `update_memory_flags(&mut stack_plus_guard_pages[(GUARD_PAGE_SIZE + stack_size)..], ...)`, protecting the same guard-sized region.
- `create_thread(..., &mut stack_plus_guard_pages[GUARD_PAGE_SIZE..(stack_size + GUARD_PAGE_SIZE)], ..., stack_size, ...)`, passing an empty stack slice and zero stack size.

In overflow-checking builds, the addition panics before returning an `io::Result`.

## Why This Is A Real Bug

The input is reachable through safe thread builder spawn paths that pass a requested stack size into the Xous backend. The backend is responsible for validating and rounding that size. Overflow during rounding breaks the size invariant and can turn a huge requested stack into a zero-length usable stack, or panic from a safe API path.

## Fix Requirement

Use checked arithmetic before rounding. If adding the page-size adjustment would overflow, return an `io::Error` instead of wrapping or panicking.

The `ThreadInit` box must not be converted with `Box::into_raw` until after fallible validation succeeds, otherwise the early error path would leak the boxed initializer.

## Patch Rationale

The patch replaces the unchecked addition with:

```rust
stack_size = stack_size
    .checked_add(4095)
    .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "invalid stack size"))?
    & !4095;
```

This preserves existing rounding behavior for valid inputs while rejecting impossible-to-round sizes with `InvalidInput`.

The patch also moves:

```rust
let data = Box::into_raw(init);
```

after the fallible stack-size validation. This prevents leaking `init` when the new checked-add path returns an error.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/thread/xous.rs b/library/std/src/sys/thread/xous.rs
index 208d43bb2c0..962684139f7 100644
--- a/library/std/src/sys/thread/xous.rs
+++ b/library/std/src/sys/thread/xous.rs
@@ -21,13 +21,17 @@ pub struct Thread {
 impl Thread {
     // unsafe: see thread::Builder::spawn_unchecked for safety requirements
     pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
-        let data = Box::into_raw(init);
         let mut stack_size = crate::cmp::max(stack, MIN_STACK_SIZE);
 
         if (stack_size & 4095) != 0 {
-            stack_size = (stack_size + 4095) & !4095;
+            stack_size = stack_size
+                .checked_add(4095)
+                .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "invalid stack size"))?
+                & !4095;
         }
 
+        let data = Box::into_raw(init);
+
         // Allocate the whole thing, then divide it up after the fact. This ensures that
         // even if there's a context switch during this function, the whole stack plus
         // guard pages will remain contiguous.
```