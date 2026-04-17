# Thread spawn panics on oversized thread id

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/thread_spawn.rs:161`

## Summary
- WASIX thread startup converts `tid.raw()` to `i32` with `try_into().map_err(|_| Errno::Overflow).unwrap()`.
- If the thread id exceeds `i32::MAX`, the conversion fails but `unwrap()` panics instead of returning `Errno::Overflow`.
- This causes the spawned thread startup path to unwind before the module callback runs.

## Provenance
- Verified from the supplied reproducer and source inspection.
- Scanner reference: https://swival.dev

## Preconditions
- A spawned thread has a raw thread id greater than `i32::MAX`.

## Proof
- In `lib/wasix/src/syscalls/wasix/thread_spawn.rs:161`, thread startup reads `ctx.data(&store).tid()`, then converts `tid.raw()` to `i32`.
- That conversion is written as `try_into().map_err(|_| Errno::Overflow).unwrap()`.
- For oversized ids, `try_into()` returns `Err`, but `unwrap()` panics, so `Errno::Overflow` is never propagated.
- The reproducer further shows this unwind occurs inside the runtime worker execution path and the module callback is never reached.
- The observed source also shows the panic can be misreported as clean thread completion when the captured thread handle is dropped during unwind.

## Why This Is A Real Bug
- The code explicitly recognizes overflow as a recoverable condition by mapping it to `Errno::Overflow`.
- Panicking instead of returning that error violates the intended error-handling path and changes externally visible behavior.
- This is not a theoretical mismatch: the oversized-id condition is reachable, including via restored thread state, and causes startup failure before guest code executes.

## Fix Requirement
- Replace the `unwrap()` on the `i32` conversion with proper error propagation that returns `Errno::Overflow`.

## Patch Rationale
- The patch in `040-thread-spawn-panics-on-oversized-thread-id.patch` removes the panic path and returns `Errno::Overflow` when `tid.raw()` does not fit in `i32`.
- This preserves the syscall’s declared error semantics and prevents unintended unwind through the runtime.

## Residual Risk
- None

## Patch
```diff
diff --git a/lib/wasix/src/syscalls/wasix/thread_spawn.rs b/lib/wasix/src/syscalls/wasix/thread_spawn.rs
--- a/lib/wasix/src/syscalls/wasix/thread_spawn.rs
+++ b/lib/wasix/src/syscalls/wasix/thread_spawn.rs
@@
-    let tid: i32 = tid.raw().try_into().map_err(|_| Errno::Overflow).unwrap();
+    let tid: i32 = tid.raw().try_into().map_err(|_| Errno::Overflow)?;
```