# wait error leaves mutex unlocked

## Classification

Resource lifecycle bug, medium severity.

## Affected Locations

`library/std/src/sys/sync/condvar/xous.rs:107`

## Summary

`Condvar::wait_ms` unlocks the associated Xous mutex before sending `WaitForCondition`. If `blocking_scalar` returns `Err`, the existing `expect` panics before the mutex is re-locked. Panic unwinding then observes an inconsistent mutex lifecycle and can cause a double-unlock or incorrect unlock through the safe `std::sync::Condvar` path.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `TicktimerScalar::WaitForCondition` is sent from `Condvar::wait_ms`.
- The Xous `blocking_scalar` call returns `Err`.
- The caller reached the backend through `wait` or `wait_timeout`, both of which call `wait_ms`.

## Proof

`wait_ms` increments `counter` and unlocks the mutex before sending `WaitForCondition`.

The vulnerable flow is:

```rust
let result = blocking_scalar(
    ticktimer_server(),
    TicktimerScalar::WaitForCondition(self.index(), ms).into(),
);
let awoken = result.expect("Ticktimer: failure to send WaitForCondition command")[0] == 0;

unsafe { mutex.lock() };
```

If `result` is `Err`, `expect` panics before `unsafe { mutex.lock() }` executes.

This is reachable from:

- `Condvar::wait`, which calls `self.wait_ms(mutex, 0)`
- `Condvar::wait_timeout`, which calls `self.wait_ms(mutex, millis)`

The reproduced impact is source-supported: safe `std::sync::Condvar::wait` holds a `MutexGuard` while calling the unsafe backend. If the backend panics after unlocking but before re-locking, unwinding drops the guard, whose destructor calls `unlock` again. With no intervening locker this can hit the Xous mutex underflow panic path; with an intervening locker it can release another thread's lock and violate mutual exclusion.

The Xous error channel is real and includes errors such as `ProcessTerminated`, `Timeout`, `ServerQueueFull`, and `InternalError`.

## Why This Is A Real Bug

The backend must restore the mutex state before returning or unwinding. `Condvar::wait_ms` temporarily releases the mutex as part of the condition-variable wait protocol, but the error path bypasses the restoration step. That leaves higher-level safe synchronization code with an invalid assumption: the `MutexGuard` being unwound still represents a locked mutex.

This is not only a panic behavior issue. The skipped re-lock can corrupt synchronization state by causing a later guard drop to unlock an already-unlocked mutex or unlock a mutex currently owned by another thread.

## Fix Requirement

On every path after `wait_ms` unlocks the mutex, the mutex must be re-locked before the function returns or panics.

For the `WaitForCondition` error path, cleanup must happen before panic propagation.

## Patch Rationale

The patch replaces the direct `expect` with error handling that re-locks the mutex before panicking:

```rust
let result = result.unwrap_or_else(|_| {
    unsafe { mutex.lock() };
    panic!("Ticktimer: failure to send WaitForCondition command");
});
let awoken = result[0] == 0;
```

This preserves the existing panic behavior and message while restoring the mutex lifecycle invariant before unwinding. The normal success path is unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/sync/condvar/xous.rs b/library/std/src/sys/sync/condvar/xous.rs
index 5d1b14443c6..05099d1c499 100644
--- a/library/std/src/sys/sync/condvar/xous.rs
+++ b/library/std/src/sys/sync/condvar/xous.rs
@@ -103,7 +103,11 @@ fn wait_ms(&self, mutex: &Mutex, ms: usize) -> bool {
             ticktimer_server(),
             TicktimerScalar::WaitForCondition(self.index(), ms).into(),
         );
-        let awoken = result.expect("Ticktimer: failure to send WaitForCondition command")[0] == 0;
+        let result = result.unwrap_or_else(|_| {
+            unsafe { mutex.lock() };
+            panic!("Ticktimer: failure to send WaitForCondition command");
+        });
+        let awoken = result[0] == 0;
 
         // If we awoke due to a timeout, increment the `timed_out` counter so that the
         // main loop of `notify` knows there's a timeout.
```