# Early Return On Atomic Wait Notification

## Classification
Logic error, medium severity.

## Affected Locations
`library/std/src/sys/thread/wasm.rs:21`

## Summary
`std::thread::sleep` on wasm uses `memory_atomic_wait32` with a timeout, but release builds ignore the wait result. If the wait returns `0` because the thread was notified before the timeout, the implementation still subtracts the full requested wait interval from the remaining duration. This can make `sleep` return earlier than the caller-provided `Duration`.

## Provenance
Reproduced and patched from the provided finding. Scanner provenance: https://swival.dev

Confidence: certain.

## Preconditions
- Target is wasm using `library/std/src/sys/thread/wasm.rs`.
- `sleep` enters the atomic-wait loop with a positive duration.
- The wasm atomic wait is externally notified before its timeout expires.

## Proof
The affected implementation stores `dur.as_nanos()` in `nanos`, then repeatedly waits for `amt = min(i64::MAX, nanos)` nanoseconds:

```rust
let val = unsafe { wasm::memory_atomic_wait32(&mut x, 0, amt as i64) };
debug_assert_eq!(val, 2);
nanos -= amt;
```

`memory_atomic_wait32` can return:
- `0` when blocked and then woken by `memory_atomic_notify`.
- `1` when the comparison fails.
- `2` when the timeout expires.

The source comment states the function expects only timeout return value `2`, but this is enforced only by `debug_assert_eq!(val, 2)`. In release builds, `val == 0` is accepted silently. The code then subtracts the full `amt` even though the elapsed time may be much smaller than `amt`.

For durations up to `i64::MAX` nanoseconds, one early notification can make `nanos` reach zero and cause `sleep` to return immediately. For longer durations, each notification can incorrectly remove one full `i64::MAX` nanosecond chunk from the remaining sleep.

## Why This Is A Real Bug
`std::thread::sleep` is expected not to sleep less than the requested duration. The wasm implementation violates that invariant when an atomic wait is notified before timeout, because it treats notification as if the entire timeout elapsed.

The bug is source-grounded:
- The wait result is captured in `val`.
- Only a debug assertion checks that `val == 2`.
- Release builds ignore non-timeout results.
- The remaining duration is decremented unconditionally.

The reproducible path is external notification via wasm atomic notify. No source support is required for true spurious wakeups to establish the bug.

## Fix Requirement
The implementation must not subtract the full requested interval unless the atomic wait actually timed out. On non-timeout returns, it must retry without decrementing the remaining duration, or otherwise subtract only measured elapsed time.

## Patch Rationale
The patch changes the loop to decrement `nanos` only when `memory_atomic_wait32` returns `2`, the timeout result:

```rust
if val == 2 {
    nanos -= amt;
}
```

This preserves the intended behavior for normal timeout-based sleeping while preventing externally notified waits from being counted as elapsed timeout duration.

## Residual Risk
None

## Patch
```diff
diff --git a/library/std/src/sys/thread/wasm.rs b/library/std/src/sys/thread/wasm.rs
index e843bc992ba..f24b23eb0ef 100644
--- a/library/std/src/sys/thread/wasm.rs
+++ b/library/std/src/sys/thread/wasm.rs
@@ -17,7 +17,8 @@ pub fn sleep(dur: Duration) {
         let amt = cmp::min(i64::MAX as u128, nanos);
         let mut x = 0;
         let val = unsafe { wasm::memory_atomic_wait32(&mut x, 0, amt as i64) };
-        debug_assert_eq!(val, 2);
-        nanos -= amt;
+        if val == 2 {
+            nanos -= amt;
+        }
     }
 }
```