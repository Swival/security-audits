# Contended Mutex Wait Path Lacks Acquire Synchronization

## Classification

Invariant violation, high severity.

## Affected Locations

`library/std/src/sys/sync/mutex/xous.rs:62`

## Summary

The Xous mutex implementation returns from the contended `lock()` wait path without performing an acquire operation after wakeup. As a result, a waiter can become the mutex owner without synchronizing with the previous owner's `Release` unlock, violating the mutex happens-before guarantee for protected data.

## Provenance

Reproduced and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

A thread acquires the mutex through the contended wait path.

## Proof

The contended path is reachable when the initial spin attempts fail and `try_lock_or_poison()` observes the mutex as already locked. In that case, `try_lock_or_poison()` increments `locked` and returns `false`, then `lock()` calls:

```rust
blocking_scalar(
    ticktimer_server(),
    crate::os::xous::services::TicktimerScalar::LockMutex(self.index()).into(),
)
.expect("failure to send LockMutex command");
```

Before the patch, `lock()` returned immediately after this syscall.

A concrete violating sequence is:

1. Thread A holds the mutex and writes protected data.
2. Thread B fails the spin attempts.
3. Thread B calls `try_lock_or_poison()`, reads `locked == 1`, and increments it to `2`.
4. Thread A unlocks with `locked.fetch_sub(1, Release)`, transitioning `2 -> 1`.
5. Thread A sends `UnlockMutex` to wake a waiter.
6. Thread B's `LockMutex` syscall returns.
7. Thread B proceeds as mutex owner without any acquire read after A's release.

`blocking_scalar` is only the Xous syscall wrapper at `library/std/src/os/xous/ffi.rs:184`; it does not perform an acquire operation on the mutex state and therefore does not synchronize with the `Release` operation in `unlock()`.

## Why This Is A Real Bug

Rust mutexes must establish a happens-before relationship between an unlock and the next successful lock. The uncontended paths perform acquire operations through `compare_exchange(..., Acquire, ...)` or `fetch_add(..., Acquire)`, but in the contended sequence the waiter's acquire happens before the previous owner's release. An acquire operation that occurs before the release cannot synchronize with that release.

Therefore, protected data written by the releasing thread is not guaranteed to be visible to the thread waking through the contended path.

## Fix Requirement

Perform an acquire operation on the mutex state after the contended waiter wakes and before `lock()` returns.

## Patch Rationale

The patch adds an acquire load of `locked` immediately after the `LockMutex` syscall returns:

```rust
let _ = self.locked.load(Acquire);
```

This ensures the contended lock path performs an acquire operation after the previous owner has released the mutex and woken the waiter. The load is intentionally placed after `blocking_scalar(...)` so the waiter does not return from `lock()` without an acquire-side synchronization point.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/sync/mutex/xous.rs b/library/std/src/sys/sync/mutex/xous.rs
index d16faa5aea3..daa6ac34487 100644
--- a/library/std/src/sys/sync/mutex/xous.rs
+++ b/library/std/src/sys/sync/mutex/xous.rs
@@ -64,6 +64,7 @@ pub unsafe fn lock(&self) {
             crate::os::xous::services::TicktimerScalar::LockMutex(self.index()).into(),
         )
         .expect("failure to send LockMutex command");
+        let _ = self.locked.load(Acquire);
     }
 
     #[inline]
```