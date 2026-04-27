# timeout result discarded in wait_timeout_while

## Classification

Logic error, medium severity, confidence certain.

## Affected Locations

`library/std/src/sync/nonpoison/condvar.rs:333`

## Summary

`Condvar::wait_timeout_while` calls `wait_timeout` inside its predicate loop but discards the returned `WaitTimeoutResult`. If the wait actually times out, and another thread changes the protected predicate to false before the waiter reacquires the mutex and rechecks the predicate, the function exits through the normal success path and returns `WaitTimeoutResult(false)`.

This misreports a real timeout as predicate satisfaction.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A caller uses the public unstable `std::sync::nonpoison::Condvar::wait_timeout_while` API.
- The call to `wait_timeout` reaches its timeout.
- Before the waiter completes the next loop condition check, another thread changes the guarded state so the predicate returns false.

## Proof

The affected implementation computes the remaining timeout, calls `self.wait_timeout(guard, timeout)`, and ignores the returned timeout status:

```rust
while condition(guard.deref_mut()) {
    let timeout = match dur.checked_sub(start.elapsed()) {
        Some(timeout) => timeout,
        None => return WaitTimeoutResult(true),
    };

    self.wait_timeout(guard, timeout);
}

WaitTimeoutResult(false)
```

A runtime proof-of-concept using the public unstable API reproduced the bug:

- One thread calls `wait_timeout_while(..., 20ms, |done| !*done)`.
- Another thread holds the mutex past the timeout, then sets `done = true` before releasing it.
- The waiter returns after about `85ms` with `timed_out=false flag=true`.

This proves the timeout elapsed, but the function reported `timed_out=false` because the predicate became false before the loop rechecked it.

## Why This Is A Real Bug

The documentation for `wait_timeout_while` states that the returned `WaitTimeoutResult` indicates whether the timeout is “known to have elapsed without the condition being met.”

In the reproduced execution, the timeout elapsed before the condition was met, but the function returned `WaitTimeoutResult(false)`. Callers relying on `timed_out()` can therefore treat a timeout as successful predicate satisfaction and skip timeout handling.

## Fix Requirement

Preserve the `WaitTimeoutResult` returned by `wait_timeout` and immediately return it when it reports that the timeout elapsed.

## Patch Rationale

The patch stores the result of `self.wait_timeout(guard, timeout)` and checks `result.timed_out()` before re-entering the predicate loop. This preserves the observable timeout event even if the guarded predicate becomes false before the next loop iteration.

Non-timeout wakeups continue to loop and re-evaluate the predicate as before.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sync/nonpoison/condvar.rs b/library/std/src/sync/nonpoison/condvar.rs
index d2b251d7c44..37b4fb11568 100644
--- a/library/std/src/sync/nonpoison/condvar.rs
+++ b/library/std/src/sync/nonpoison/condvar.rs
@@ -331,7 +331,10 @@ pub fn wait_timeout_while<T, F>(
                 None => return WaitTimeoutResult(true),
             };
 
-            self.wait_timeout(guard, timeout);
+            let result = self.wait_timeout(guard, timeout);
+            if result.timed_out() {
+                return result;
+            }
         }
 
         WaitTimeoutResult(false)
```