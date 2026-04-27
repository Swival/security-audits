# notify error loses waiters

## Classification

Error-handling bug. Severity: medium. Confidence: certain.

## Affected Locations

- `library/std/src/sys/sync/condvar/xous.rs:63`

## Summary

`Condvar::notify_some` decrements the recorded waiter count before sending `TicktimerScalar::NotifyCondition`. If the send fails, the existing `.expect(...)` panics without restoring the decremented count. When that panic unwinds and is caught, the condvar state remains corrupted: a real waiter can remain blocked while `counter` says there are no waiters, causing later `notify_one` or `notify_all` calls to skip notification.

## Provenance

Verified by reproduced finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `NotifyCondition` returns an error.
- At least one waiter is recorded in `Condvar::counter`.
- The panic from the failed notify path unwinds and is caught, allowing the corrupted condvar to continue being used.

## Proof

`notify_one` and `notify_all` both call `notify_some`.

Inside `notify_some`, `counter.try_update(...)` subtracts the intended notification count before the Xous ticktimer notification is sent. With one waiter and `notify_one`, this changes `counter` from `1` to `0`.

The following call can fail:

```rust
blocking_scalar(
    ticktimer_server(),
    TicktimerScalar::NotifyCondition(self.index(), remaining_to_wake).into(),
)
```

`blocking_scalar` maps `SyscallResult::Error` to `Err` at `library/std/src/os/xous/ffi.rs:220`. The original condvar code immediately called:

```rust
.expect("failure to send NotifyCondition command")
```

on that result.

If the send fails, the panic occurs after `counter` was decremented and before any waiter was notified. On Xous, `riscv32imac_unknown_xous_elf` uses unwind panics, and `std::panic::catch_unwind` is available, so the panic can be caught. The blocked waiter remains in `WaitForCondition`, but the condvar accounting now says there are no waiters.

A later `notify_one` observes `counter == 0`; `try_update` returns `Err`, and `notify_some` returns without sending `NotifyCondition`. `notify_all` similarly computes zero waiters and sends nothing.

## Why This Is A Real Bug

The implementation relies on `counter` tracking waiters that still require notification. The failed-notify path violates that invariant by removing waiters from `counter` before the notification succeeds.

This is not only a panic-path cosmetic issue: because Xous supports unwind panics, callers can catch the panic and continue using the same condvar. After that, the condvar can permanently lose track of an actually blocked waiter, making future notifications ineffective for that waiter.

## Fix Requirement

On `NotifyCondition` error, restore the waiter count that was pre-decremented before propagating the failure.

## Patch Rationale

The patch replaces the direct `.expect(...)` with explicit `match` handling:

```rust
let result = match blocking_scalar(
    ticktimer_server(),
    TicktimerScalar::NotifyCondition(self.index(), remaining_to_wake).into(),
) {
    Ok(result) => result,
    Err(err) => {
        self.counter.fetch_add(remaining_to_wake, Ordering::Relaxed);
        panic!("failure to send NotifyCondition command: {err:?}");
    }
};
```

This restores `remaining_to_wake` into `counter` before panicking. Since `remaining_to_wake` is the number of waiters already removed from the local accounting and not yet reported as notified by the ticktimer, adding it back preserves the condvar invariant across unwind.

The patch keeps the existing failure behavior of panicking on failed `NotifyCondition`, while preventing the panic from corrupting waiter accounting.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/sync/condvar/xous.rs b/library/std/src/sys/sync/condvar/xous.rs
index 5d1b14443c6..ecdbb92097f 100644
--- a/library/std/src/sys/sync/condvar/xous.rs
+++ b/library/std/src/sys/sync/condvar/xous.rs
@@ -55,11 +55,16 @@ fn notify_some(&self, to_notify: usize) {
             return;
         }
         for _wake_tries in 0..NOTIFY_TRIES {
-            let result = blocking_scalar(
+            let result = match blocking_scalar(
                 ticktimer_server(),
                 TicktimerScalar::NotifyCondition(self.index(), remaining_to_wake).into(),
-            )
-            .expect("failure to send NotifyCondition command");
+            ) {
+                Ok(result) => result,
+                Err(err) => {
+                    self.counter.fetch_add(remaining_to_wake, Ordering::Relaxed);
+                    panic!("failure to send NotifyCondition command: {err:?}");
+                }
+            };
 
             // Remove the list of waiters that were notified
             remaining_to_wake -= result[0];
```